// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::arch::x86_64::__cpuid;

use base::IoctlNr;

use libc::E2BIG;

use base::{
    errno_result, error, ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr,
    ioctl_with_ref, ioctl_with_val, AsRawDescriptor, Error, MappedRegion, Result,
};
use data_model::vec_with_array_field;
use kvm_sys::*;
use vm_memory::GuestAddress;

use super::{Kvm, KvmVcpu, KvmVm};
use crate::{
    ClockState, CpuId, CpuIdEntry, DebugRegs, DescriptorTable, DeviceKind, Fpu, HypervisorX86_64,
    IoapicRedirectionTableEntry, IoapicState, IrqSourceChip, LapicState, PicSelect, PicState,
    PitChannelState, PitState, ProtectionType, Register, Regs, Segment, Sregs, VcpuExit,
    VcpuX86_64, VmCap, VmX86_64, MAX_IOAPIC_PINS, NUM_IOAPIC_PINS,
};

type KvmCpuId = kvm::CpuId;

fn get_cpuid_with_initial_capacity<T: AsRawDescriptor>(
    descriptor: &T,
    kind: IoctlNr,
    initial_capacity: usize,
) -> Result<CpuId> {
    let mut entries: usize = initial_capacity;

    loop {
        let mut kvm_cpuid = KvmCpuId::new(entries);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the
            // memory allocated for the struct. The limit is read from nent within KvmCpuId,
            // which is set to the allocated size above.
            ioctl_with_mut_ptr(descriptor, kind, kvm_cpuid.as_mut_ptr())
        };
        if ret < 0 {
            let err = Error::last();
            match err.errno() {
                E2BIG => {
                    // double the available memory for cpuid entries for kvm.
                    if let Some(val) = entries.checked_mul(2) {
                        entries = val;
                    } else {
                        return Err(err);
                    }
                }
                _ => return Err(err),
            }
        } else {
            return Ok(CpuId::from(&kvm_cpuid));
        }
    }
}

impl Kvm {
    pub fn get_cpuid(&self, kind: IoctlNr) -> Result<CpuId> {
        const KVM_MAX_ENTRIES: usize = 256;
        get_cpuid_with_initial_capacity(self, kind, KVM_MAX_ENTRIES)
    }

    // The x86 machine type is always 0. Protected VMs are not supported.
    pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
        if protection_type == ProtectionType::Unprotected {
            Ok(0)
        } else {
            error!("Protected mode is not supported on x86_64.");
            Err(Error::new(libc::EINVAL))
        }
    }

    /// Get the size of guest physical addresses in bits.
    pub fn get_guest_phys_addr_bits(&self) -> u8 {
        // Get host cpu max physical address bits.
        // Assume the guest physical address size is the same as the host.
        let highest_ext_function = unsafe { __cpuid(0x80000000) };
        if highest_ext_function.eax >= 0x80000008 {
            let addr_size = unsafe { __cpuid(0x80000008) };
            // Low 8 bits of 0x80000008 leaf: host physical address size in bits.
            addr_size.eax as u8
        } else {
            36
        }
    }
}

impl HypervisorX86_64 for Kvm {
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID())
    }

    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID())
    }

    fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        const MAX_KVM_MSR_ENTRIES: usize = 256;

        let mut msr_list = vec_with_array_field::<kvm_msr_list, u32>(MAX_KVM_MSR_ENTRIES);
        msr_list[0].nmsrs = MAX_KVM_MSR_ENTRIES as u32;

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
            // size (MAX_KVM_MSR_ENTRIES) above.
            ioctl_with_mut_ref(self, KVM_GET_MSR_INDEX_LIST(), &mut msr_list[0])
        };
        if ret < 0 {
            return errno_result();
        }

        let mut nmsrs = msr_list[0].nmsrs;

        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        let indices: &[u32] = unsafe {
            if nmsrs > MAX_KVM_MSR_ENTRIES as u32 {
                nmsrs = MAX_KVM_MSR_ENTRIES as u32;
            }
            msr_list[0].indices.as_slice(nmsrs as usize)
        };

        Ok(indices.to_vec())
    }
}

impl KvmVm {
    /// Checks if a particular `VmCap` is available, or returns None if arch-independent
    /// Vm.check_capability() should handle the check.
    pub fn check_capability_arch(&self, c: VmCap) -> Option<bool> {
        match c {
            VmCap::PvClock => Some(true),
            _ => None,
        }
    }

    /// Returns the params to pass to KVM_CREATE_DEVICE for a `kind` device on this arch, or None to
    /// let the arch-independent `KvmVm::create_device` handle it.
    pub fn get_device_params_arch(&self, _kind: DeviceKind) -> Option<kvm_create_device> {
        None
    }

    /// Arch-specific implementation of `Vm::get_pvclock`.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        // Safe because we know that our file is a VM fd, we know the kernel will only write correct
        // amount of memory to our pointer, and we verify the return result.
        let mut clock_data: kvm_clock_data = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_CLOCK(), &mut clock_data) };
        if ret == 0 {
            Ok(ClockState::from(clock_data))
        } else {
            errno_result()
        }
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.
    pub fn set_pvclock_arch(&self, state: &ClockState) -> Result<()> {
        let clock_data = kvm_clock_data::from(*state);
        // Safe because we know that our file is a VM fd, we know the kernel will only read correct
        // amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_CLOCK(), &clock_data) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of given interrupt controller by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn get_pic_state(&self, id: PicSelect) -> Result<kvm_pic_state> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: id as u32,
            ..Default::default()
        };
        let ret = unsafe {
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state)
        };
        if ret == 0 {
            Ok(unsafe {
                // Safe as we know that we are retrieving data related to the
                // PIC (primary or secondary) and not IOAPIC.
                irqchip_state.chip.pic
            })
        } else {
            errno_result()
        }
    }

    /// Sets the state of given interrupt controller by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn set_pic_state(&self, id: PicSelect, state: &kvm_pic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: id as u32,
            ..Default::default()
        };
        irqchip_state.chip.pic = *state;
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the KVM_IOAPIC_NUM_PINS value for emulated IO-APIC.
    pub fn get_ioapic_num_pins(&self) -> Result<usize> {
        // Safe because we know that our file is a KVM fd, and if the cap is invalid KVM assumes
        // it's an unavailable extension and returns 0, producing default KVM_IOAPIC_NUM_PINS value.
        match unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), KVM_CAP_IOAPIC_NUM_PINS as u64) }
        {
            ret if ret < 0 => errno_result(),
            ret => Ok((ret as usize).max(NUM_IOAPIC_PINS).min(MAX_IOAPIC_PINS)),
        }
    }

    /// Retrieves the state of IOAPIC by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn get_ioapic_state(&self) -> Result<kvm_ioapic_state> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: 2,
            ..Default::default()
        };
        let ret = unsafe {
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state)
        };
        if ret == 0 {
            Ok(unsafe {
                // Safe as we know that we are retrieving data related to the
                // IOAPIC and not PIC.
                irqchip_state.chip.ioapic
            })
        } else {
            errno_result()
        }
    }

    /// Sets the state of IOAPIC by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn set_ioapic_state(&self, state: &kvm_ioapic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: 2,
            ..Default::default()
        };
        irqchip_state.chip.ioapic = *state;
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Creates a PIT as per the KVM_CREATE_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn create_pit(&self) -> Result<()> {
        let pit_config = kvm_pit_config::default();
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_PIT2(), &pit_config) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of PIT by issuing KVM_GET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    pub fn get_pit_state(&self) -> Result<kvm_pit_state2> {
        // Safe because we know that our file is a VM fd, we know the kernel will only write
        // correct amount of memory to our pointer, and we verify the return result.
        let mut pit_state = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_PIT2(), &mut pit_state) };
        if ret == 0 {
            Ok(pit_state)
        } else {
            errno_result()
        }
    }

    /// Sets the state of PIT by issuing KVM_SET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    pub fn set_pit_state(&self, pit_state: &kvm_pit_state2) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_PIT2(), pit_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Enable userspace msr.
    pub fn enable_userspace_msr(&self) -> Result<()> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_X86_USER_SPACE_MSR,
            ..Default::default()
        };
        cap.args[0] = (KVM_MSR_EXIT_REASON_UNKNOWN
            | KVM_MSR_EXIT_REASON_INVAL
            | KVM_MSR_EXIT_REASON_FILTER) as u64;
        // TODO(b/215297064): Filter only the ones we care about with ioctl
        // KVM_X86_SET_MSR_FILTER

        // Safe because we know that our file is a VM fd, we know that the
        // kernel will only read correct amount of memory from our pointer, and
        // we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), &cap) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }

    /// Enable support for split-irqchip.
    pub fn enable_split_irqchip(&self, ioapic_pins: usize) -> Result<()> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = ioapic_pins as u64;
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), &cap) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }
}

impl VmX86_64 for KvmVm {
    fn get_hypervisor(&self) -> &dyn HypervisorX86_64 {
        &self.kvm
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuX86_64>> {
        // create_vcpu is declared separately in VmAArch64 and VmX86, so it can return VcpuAArch64
        // or VcpuX86.  But both use the same implementation in KvmVm::create_vcpu.
        Ok(Box::new(KvmVm::create_vcpu(self, id)?))
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_TSS_ADDR ioctl.
    fn set_tss_addr(&self, addr: GuestAddress) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSS_ADDR(), addr.offset() as u64) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the address of a one-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_IDENTITY_MAP_ADDR ioctl.
    fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret =
            unsafe { ioctl_with_ref(self, KVM_SET_IDENTITY_MAP_ADDR(), &(addr.offset() as u64)) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

impl KvmVcpu {
    /// Arch-specific implementation of `Vcpu::pvclock_ctrl`.
    pub fn pvclock_ctrl_arch(&self) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because it does not read or write memory in this process.
            ioctl(self, KVM_KVMCLOCK_CTRL())
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Handles a `KVM_EXIT_SYSTEM_EVENT` with event type `KVM_SYSTEM_EVENT_RESET` with the given
    /// event flags and returns the appropriate `VcpuExit` value for the run loop to handle.
    pub fn system_event_reset(&self, _event_flags: u64) -> Result<VcpuExit> {
        Ok(VcpuExit::SystemEventReset)
    }
}

impl VcpuX86_64 for KvmVcpu {
    #[allow(clippy::cast_ptr_alignment)]
    fn set_interrupt_window_requested(&self, requested: bool) {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        run.request_interrupt_window = if requested { 1 } else { 0 };
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn ready_for_interrupt(&self) -> bool {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        run.ready_for_interrupt_injection != 0 && run.if_flag != 0
    }

    /// Use the KVM_INTERRUPT ioctl to inject the specified interrupt vector.
    ///
    /// While this ioctl exists on PPC and MIPS as well as x86, the semantics are different and
    /// ChromeOS doesn't support PPC or MIPS.
    fn interrupt(&self, irq: u32) -> Result<()> {
        let interrupt = kvm_interrupt { irq };
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_INTERRUPT(), &interrupt) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn inject_nmi(&self) -> Result<()> {
        // Safe because we know that our file is a VCPU fd.
        let ret = unsafe { ioctl(self, KVM_NMI()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_regs(&self) -> Result<Regs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let mut regs: kvm_regs = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) };
        if ret == 0 {
            Ok(Regs::from(&regs))
        } else {
            errno_result()
        }
    }

    fn set_regs(&self, regs: &Regs) -> Result<()> {
        let regs = kvm_regs::from(regs);
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_REGS(), &regs) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_sregs(&self) -> Result<Sregs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs: kvm_sregs = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret == 0 {
            Ok(Sregs::from(&regs))
        } else {
            errno_result()
        }
    }

    fn set_sregs(&self, sregs: &Sregs) -> Result<()> {
        let sregs = kvm_sregs::from(sregs);
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), &sregs) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_fpu(&self) -> Result<Fpu> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut fpu: kvm_fpu = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut fpu) };
        if ret == 0 {
            Ok(Fpu::from(&fpu))
        } else {
            errno_result()
        }
    }

    fn set_fpu(&self, fpu: &Fpu) -> Result<()> {
        let fpu = kvm_fpu::from(fpu);
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_ref(self, KVM_SET_FPU(), &fpu)
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_debugregs(&self) -> Result<DebugRegs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs: kvm_debugregs = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_DEBUGREGS(), &mut regs) };
        if ret == 0 {
            Ok(DebugRegs::from(&regs))
        } else {
            errno_result()
        }
    }

    fn set_debugregs(&self, dregs: &DebugRegs) -> Result<()> {
        let dregs = kvm_debugregs::from(dregs);
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_debugregs struct.
            ioctl_with_ref(self, KVM_SET_DEBUGREGS(), &dregs)
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_xcrs(&self) -> Result<Vec<Register>> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs: kvm_xcrs = Default::default();
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_XCRS(), &mut regs) };
        if ret == 0 {
            Ok(from_kvm_xcrs(&regs))
        } else {
            errno_result()
        }
    }

    fn set_xcrs(&self, xcrs: &[Register]) -> Result<()> {
        let xcrs = to_kvm_xcrs(xcrs);
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_xcrs struct.
            ioctl_with_ref(self, KVM_SET_XCRS(), &xcrs)
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_msrs(&self, vec: &mut Vec<Register>) -> Result<()> {
        let msrs = to_kvm_msrs(vec);
        let ret = unsafe {
            // Here we trust the kernel not to read or write past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_GET_MSRS(), &msrs[0])
        };
        // KVM_GET_MSRS actually returns the number of msr entries written.
        if ret < 0 {
            return errno_result();
        }
        // Safe because we trust the kernel to return the correct array length on success.
        let entries = unsafe {
            let count = ret as usize;
            assert!(count <= vec.len());
            msrs[0].entries.as_slice(count)
        };
        vec.truncate(0);
        vec.extend(entries.iter().map(|e| Register {
            id: e.index,
            value: e.data,
        }));
        Ok(())
    }

    fn set_msrs(&self, vec: &[Register]) -> Result<()> {
        let msrs = to_kvm_msrs(vec);
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_SET_MSRS(), &msrs[0])
        };
        // KVM_SET_MSRS actually returns the number of msr entries written.
        if ret >= 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn set_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        let cpuid = KvmCpuId::from(cpuid);
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_ptr())
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_hyperv_cpuid(&self) -> Result<CpuId> {
        const KVM_MAX_ENTRIES: usize = 256;
        get_cpuid_with_initial_capacity(self, KVM_GET_SUPPORTED_HV_CPUID(), KVM_MAX_ENTRIES)
    }

    fn set_guest_debug(&self, addrs: &[GuestAddress], enable_singlestep: bool) -> Result<()> {
        use kvm_sys::*;
        let mut dbg: kvm_guest_debug = Default::default();

        if addrs.len() > 4 {
            error!(
                "Support 4 breakpoints at most but {} addresses are passed",
                addrs.len()
            );
            return Err(base::Error::new(libc::EINVAL));
        }

        dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
        if enable_singlestep {
            dbg.control |= KVM_GUESTDBG_SINGLESTEP;
        }

        // Set bits 9 and 10.
        // bit 9: GE (global exact breakpoint enable) flag.
        // bit 10: always 1.
        dbg.arch.debugreg[7] = 0x0600;

        for (i, addr) in addrs.iter().enumerate() {
            dbg.arch.debugreg[i] = addr.0;
            // Set global breakpoint enable flag
            dbg.arch.debugreg[7] |= 2 << (i * 2);
        }

        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_guest_debug struct.
            ioctl_with_ref(self, KVM_SET_GUEST_DEBUG(), &dbg)
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

impl KvmVcpu {
    /// X86 specific call to get the state of the "Local Advanced Programmable Interrupt Controller".
    ///
    /// See the documentation for KVM_GET_LAPIC.
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic: kvm_lapic_state = Default::default();

        let ret = unsafe {
            // The ioctl is unsafe unless you trust the kernel not to write past the end of the
            // local_apic struct.
            ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(klapic)
    }

    /// X86 specific call to set the state of the "Local Advanced Programmable Interrupt Controller".
    ///
    /// See the documentation for KVM_SET_LAPIC.
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the klapic struct.
            ioctl_with_ref(self, KVM_SET_LAPIC(), klapic)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

impl<'a> From<&'a KvmCpuId> for CpuId {
    fn from(kvm_cpuid: &'a KvmCpuId) -> CpuId {
        let kvm_entries = kvm_cpuid.entries_slice();
        let mut cpu_id_entries = Vec::with_capacity(kvm_entries.len());

        for entry in kvm_entries {
            let cpu_id_entry = CpuIdEntry {
                function: entry.function,
                index: entry.index,
                flags: entry.flags,
                eax: entry.eax,
                ebx: entry.ebx,
                ecx: entry.ecx,
                edx: entry.edx,
            };
            cpu_id_entries.push(cpu_id_entry)
        }
        CpuId { cpu_id_entries }
    }
}

impl From<&CpuId> for KvmCpuId {
    fn from(cpuid: &CpuId) -> KvmCpuId {
        let mut kvm = KvmCpuId::new(cpuid.cpu_id_entries.len());
        let entries = kvm.mut_entries_slice();
        for (i, &e) in cpuid.cpu_id_entries.iter().enumerate() {
            entries[i] = kvm_cpuid_entry2 {
                function: e.function,
                index: e.index,
                flags: e.flags,
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
                ..Default::default()
            };
        }
        kvm
    }
}

impl From<ClockState> for kvm_clock_data {
    fn from(state: ClockState) -> Self {
        kvm_clock_data {
            clock: state.clock,
            flags: state.flags,
            ..Default::default()
        }
    }
}

impl From<kvm_clock_data> for ClockState {
    fn from(clock_data: kvm_clock_data) -> Self {
        ClockState {
            clock: clock_data.clock,
            flags: clock_data.flags,
        }
    }
}

impl From<&kvm_pic_state> for PicState {
    fn from(item: &kvm_pic_state) -> Self {
        PicState {
            last_irr: item.last_irr,
            irr: item.irr,
            imr: item.imr,
            isr: item.isr,
            priority_add: item.priority_add,
            irq_base: item.irq_base,
            read_reg_select: item.read_reg_select != 0,
            poll: item.poll != 0,
            special_mask: item.special_mask != 0,
            init_state: item.init_state.into(),
            auto_eoi: item.auto_eoi != 0,
            rotate_on_auto_eoi: item.rotate_on_auto_eoi != 0,
            special_fully_nested_mode: item.special_fully_nested_mode != 0,
            use_4_byte_icw: item.init4 != 0,
            elcr: item.elcr,
            elcr_mask: item.elcr_mask,
        }
    }
}

impl From<&PicState> for kvm_pic_state {
    fn from(item: &PicState) -> Self {
        kvm_pic_state {
            last_irr: item.last_irr,
            irr: item.irr,
            imr: item.imr,
            isr: item.isr,
            priority_add: item.priority_add,
            irq_base: item.irq_base,
            read_reg_select: item.read_reg_select as u8,
            poll: item.poll as u8,
            special_mask: item.special_mask as u8,
            init_state: item.init_state as u8,
            auto_eoi: item.auto_eoi as u8,
            rotate_on_auto_eoi: item.rotate_on_auto_eoi as u8,
            special_fully_nested_mode: item.special_fully_nested_mode as u8,
            init4: item.use_4_byte_icw as u8,
            elcr: item.elcr,
            elcr_mask: item.elcr_mask,
        }
    }
}

impl From<&kvm_ioapic_state> for IoapicState {
    fn from(item: &kvm_ioapic_state) -> Self {
        let mut state = IoapicState {
            base_address: item.base_address,
            ioregsel: item.ioregsel as u8,
            ioapicid: item.id,
            current_interrupt_level_bitmap: item.irr,
            redirect_table: [IoapicRedirectionTableEntry::default(); 120],
        };
        for (in_state, out_state) in item.redirtbl.iter().zip(state.redirect_table.iter_mut()) {
            *out_state = in_state.into();
        }
        state
    }
}

impl From<&IoapicRedirectionTableEntry> for kvm_ioapic_state__bindgen_ty_1 {
    fn from(item: &IoapicRedirectionTableEntry) -> Self {
        kvm_ioapic_state__bindgen_ty_1 {
            // IoapicRedirectionTableEntry layout matches the exact bit layout of a hardware
            // ioapic redirection table entry, so we can simply do a 64-bit copy
            bits: item.get(0, 64),
        }
    }
}

impl From<&kvm_ioapic_state__bindgen_ty_1> for IoapicRedirectionTableEntry {
    fn from(item: &kvm_ioapic_state__bindgen_ty_1) -> Self {
        let mut entry = IoapicRedirectionTableEntry::default();
        // Safe because the 64-bit layout of the IoapicRedirectionTableEntry matches the kvm_sys
        // table entry layout
        entry.set(0, 64, unsafe { item.bits as u64 });
        entry
    }
}

impl From<&IoapicState> for kvm_ioapic_state {
    fn from(item: &IoapicState) -> Self {
        let mut state = kvm_ioapic_state {
            base_address: item.base_address,
            ioregsel: item.ioregsel as u32,
            id: item.ioapicid,
            irr: item.current_interrupt_level_bitmap,
            ..Default::default()
        };
        for (in_state, out_state) in item.redirect_table.iter().zip(state.redirtbl.iter_mut()) {
            *out_state = in_state.into();
        }
        state
    }
}

impl From<&LapicState> for kvm_lapic_state {
    fn from(item: &LapicState) -> Self {
        let mut state = kvm_lapic_state::default();
        // There are 64 lapic registers
        for (reg, value) in item.regs.iter().enumerate() {
            // Each lapic register is 16 bytes, but only the first 4 are used
            let reg_offset = 16 * reg;
            let regs_slice = &mut state.regs[reg_offset..reg_offset + 4];

            // to_le_bytes() produces an array of u8, not i8(c_char), so we can't directly use
            // copy_from_slice().
            for (i, v) in value.to_le_bytes().iter().enumerate() {
                regs_slice[i] = *v as i8;
            }
        }
        state
    }
}

impl From<&kvm_lapic_state> for LapicState {
    fn from(item: &kvm_lapic_state) -> Self {
        let mut state = LapicState { regs: [0; 64] };
        // There are 64 lapic registers
        for reg in 0..64 {
            // Each lapic register is 16 bytes, but only the first 4 are used
            let reg_offset = 16 * reg;

            // from_le_bytes() only works on arrays of u8, not i8(c_char).
            let reg_slice = &item.regs[reg_offset..reg_offset + 4];
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                bytes[i] = reg_slice[i] as u8;
            }
            state.regs[reg] = u32::from_le_bytes(bytes);
        }
        state
    }
}

impl From<&PitState> for kvm_pit_state2 {
    fn from(item: &PitState) -> Self {
        kvm_pit_state2 {
            channels: [
                kvm_pit_channel_state::from(&item.channels[0]),
                kvm_pit_channel_state::from(&item.channels[1]),
                kvm_pit_channel_state::from(&item.channels[2]),
            ],
            flags: item.flags,
            ..Default::default()
        }
    }
}

impl From<&kvm_pit_state2> for PitState {
    fn from(item: &kvm_pit_state2) -> Self {
        PitState {
            channels: [
                PitChannelState::from(&item.channels[0]),
                PitChannelState::from(&item.channels[1]),
                PitChannelState::from(&item.channels[2]),
            ],
            flags: item.flags,
        }
    }
}

impl From<&PitChannelState> for kvm_pit_channel_state {
    fn from(item: &PitChannelState) -> Self {
        kvm_pit_channel_state {
            count: item.count,
            latched_count: item.latched_count,
            count_latched: item.count_latched as u8,
            status_latched: item.status_latched as u8,
            status: item.status,
            read_state: item.read_state as u8,
            write_state: item.write_state as u8,
            // kvm's write_latch only stores the low byte of the reload value
            write_latch: item.reload_value as u8,
            rw_mode: item.rw_mode as u8,
            mode: item.mode,
            bcd: item.bcd as u8,
            gate: item.gate as u8,
            count_load_time: item.count_load_time as i64,
        }
    }
}

impl From<&kvm_pit_channel_state> for PitChannelState {
    fn from(item: &kvm_pit_channel_state) -> Self {
        PitChannelState {
            count: item.count,
            latched_count: item.latched_count,
            count_latched: item.count_latched.into(),
            status_latched: item.status_latched != 0,
            status: item.status,
            read_state: item.read_state.into(),
            write_state: item.write_state.into(),
            // kvm's write_latch only stores the low byte of the reload value
            reload_value: item.write_latch as u16,
            rw_mode: item.rw_mode.into(),
            mode: item.mode,
            bcd: item.bcd != 0,
            gate: item.gate != 0,
            count_load_time: item.count_load_time as u64,
        }
    }
}

// This function translates an IrqSrouceChip to the kvm u32 equivalent. It has a different
// implementation between x86_64 and aarch64 because the irqchip KVM constants are not defined on
// all architectures.
pub(super) fn chip_to_kvm_chip(chip: IrqSourceChip) -> u32 {
    match chip {
        IrqSourceChip::PicPrimary => KVM_IRQCHIP_PIC_MASTER,
        IrqSourceChip::PicSecondary => KVM_IRQCHIP_PIC_SLAVE,
        IrqSourceChip::Ioapic => KVM_IRQCHIP_IOAPIC,
        _ => {
            error!("Invalid IrqChipSource for X86 {:?}", chip);
            0
        }
    }
}

impl From<&kvm_regs> for Regs {
    fn from(r: &kvm_regs) -> Self {
        Regs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.rflags,
        }
    }
}

impl From<&Regs> for kvm_regs {
    fn from(r: &Regs) -> Self {
        kvm_regs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.rflags,
        }
    }
}

impl From<&kvm_segment> for Segment {
    fn from(s: &kvm_segment) -> Self {
        Segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
        }
    }
}

impl From<&Segment> for kvm_segment {
    fn from(s: &Segment) -> Self {
        kvm_segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            unusable: match s.present {
                0 => 1,
                _ => 0,
            },
            ..Default::default()
        }
    }
}

impl From<&kvm_dtable> for DescriptorTable {
    fn from(dt: &kvm_dtable) -> Self {
        DescriptorTable {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

impl From<&DescriptorTable> for kvm_dtable {
    fn from(dt: &DescriptorTable) -> Self {
        kvm_dtable {
            base: dt.base,
            limit: dt.limit,
            ..Default::default()
        }
    }
}

impl From<&kvm_sregs> for Sregs {
    fn from(r: &kvm_sregs) -> Self {
        Sregs {
            cs: Segment::from(&r.cs),
            ds: Segment::from(&r.ds),
            es: Segment::from(&r.es),
            fs: Segment::from(&r.fs),
            gs: Segment::from(&r.gs),
            ss: Segment::from(&r.ss),
            tr: Segment::from(&r.tr),
            ldt: Segment::from(&r.ldt),
            gdt: DescriptorTable::from(&r.gdt),
            idt: DescriptorTable::from(&r.idt),
            cr0: r.cr0,
            cr2: r.cr2,
            cr3: r.cr3,
            cr4: r.cr4,
            cr8: r.cr8,
            efer: r.efer,
            apic_base: r.apic_base,
            interrupt_bitmap: r.interrupt_bitmap,
        }
    }
}

impl From<&Sregs> for kvm_sregs {
    fn from(r: &Sregs) -> Self {
        kvm_sregs {
            cs: kvm_segment::from(&r.cs),
            ds: kvm_segment::from(&r.ds),
            es: kvm_segment::from(&r.es),
            fs: kvm_segment::from(&r.fs),
            gs: kvm_segment::from(&r.gs),
            ss: kvm_segment::from(&r.ss),
            tr: kvm_segment::from(&r.tr),
            ldt: kvm_segment::from(&r.ldt),
            gdt: kvm_dtable::from(&r.gdt),
            idt: kvm_dtable::from(&r.idt),
            cr0: r.cr0,
            cr2: r.cr2,
            cr3: r.cr3,
            cr4: r.cr4,
            cr8: r.cr8,
            efer: r.efer,
            apic_base: r.apic_base,
            interrupt_bitmap: r.interrupt_bitmap,
        }
    }
}

impl From<&kvm_fpu> for Fpu {
    fn from(r: &kvm_fpu) -> Self {
        Fpu {
            fpr: r.fpr,
            fcw: r.fcw,
            fsw: r.fsw,
            ftwx: r.ftwx,
            last_opcode: r.last_opcode,
            last_ip: r.last_ip,
            last_dp: r.last_dp,
            xmm: r.xmm,
            mxcsr: r.mxcsr,
        }
    }
}

impl From<&Fpu> for kvm_fpu {
    fn from(r: &Fpu) -> Self {
        kvm_fpu {
            fpr: r.fpr,
            fcw: r.fcw,
            fsw: r.fsw,
            ftwx: r.ftwx,
            last_opcode: r.last_opcode,
            last_ip: r.last_ip,
            last_dp: r.last_dp,
            xmm: r.xmm,
            mxcsr: r.mxcsr,
            ..Default::default()
        }
    }
}

impl From<&kvm_debugregs> for DebugRegs {
    fn from(r: &kvm_debugregs) -> Self {
        DebugRegs {
            db: r.db,
            dr6: r.dr6,
            dr7: r.dr7,
        }
    }
}

impl From<&DebugRegs> for kvm_debugregs {
    fn from(r: &DebugRegs) -> Self {
        kvm_debugregs {
            db: r.db,
            dr6: r.dr6,
            dr7: r.dr7,
            ..Default::default()
        }
    }
}

fn from_kvm_xcrs(r: &kvm_xcrs) -> Vec<Register> {
    r.xcrs
        .iter()
        .take(r.nr_xcrs as usize)
        .map(|x| Register {
            id: x.xcr,
            value: x.value,
        })
        .collect()
}

fn to_kvm_xcrs(r: &[Register]) -> kvm_xcrs {
    let mut kvm = kvm_xcrs {
        nr_xcrs: r.len() as u32,
        ..Default::default()
    };
    for (i, &xcr) in r.iter().enumerate() {
        kvm.xcrs[i].xcr = xcr.id as u32;
        kvm.xcrs[i].value = xcr.value;
    }
    kvm
}

fn to_kvm_msrs(vec: &[Register]) -> Vec<kvm_msrs> {
    let vec: Vec<kvm_msr_entry> = vec
        .iter()
        .map(|e| kvm_msr_entry {
            index: e.id as u32,
            data: e.value,
            ..Default::default()
        })
        .collect();

    let mut msrs = vec_with_array_field::<kvm_msrs, kvm_msr_entry>(vec.len());
    unsafe {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.
        // Providing the length used to create the struct guarantees the entire slice is valid.
        msrs[0]
            .entries
            .as_mut_slice(vec.len())
            .copy_from_slice(&vec);
    }
    msrs[0].nmsrs = vec.len() as u32;
    msrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeliveryMode, DeliveryStatus, DestinationMode, Hypervisor, HypervisorCap, HypervisorX86_64,
        IoapicRedirectionTableEntry, IoapicState, IrqRoute, IrqSource, IrqSourceChip, LapicState,
        PicInitState, PicState, PitChannelState, PitRWMode, PitRWState, PitState, TriggerMode,
        Vcpu, Vm,
    };
    use libc::EINVAL;
    use vm_memory::{GuestAddress, GuestMemory};

    #[test]
    fn get_supported_cpuid() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor.get_supported_cpuid().unwrap();
        assert!(cpuid.cpu_id_entries.len() > 0);
    }

    #[test]
    fn get_emulated_cpuid() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor.get_emulated_cpuid().unwrap();
        assert!(cpuid.cpu_id_entries.len() > 0);
    }

    #[test]
    fn get_msr_index_list() {
        let kvm = Kvm::new().unwrap();
        let msr_list = kvm.get_msr_index_list().unwrap();
        assert!(msr_list.len() >= 2);
    }

    #[test]
    fn entries_double_on_error() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid =
            get_cpuid_with_initial_capacity(&hypervisor, KVM_GET_SUPPORTED_CPUID(), 4).unwrap();
        assert!(cpuid.cpu_id_entries.len() > 4);
    }

    #[test]
    fn check_vm_arch_capability() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        assert!(vm.check_capability(VmCap::PvClock));
    }

    #[test]
    fn pic_state() {
        let state = PicState {
            last_irr: 0b00000001,
            irr: 0b00000010,
            imr: 0b00000100,
            isr: 0b00001000,
            priority_add: 0b00010000,
            irq_base: 0b00100000,
            read_reg_select: false,
            poll: true,
            special_mask: true,
            init_state: PicInitState::Icw3,
            auto_eoi: true,
            rotate_on_auto_eoi: false,
            special_fully_nested_mode: true,
            use_4_byte_icw: true,
            elcr: 0b01000000,
            elcr_mask: 0b10000000,
        };

        let kvm_state = kvm_pic_state::from(&state);

        assert_eq!(kvm_state.last_irr, 0b00000001);
        assert_eq!(kvm_state.irr, 0b00000010);
        assert_eq!(kvm_state.imr, 0b00000100);
        assert_eq!(kvm_state.isr, 0b00001000);
        assert_eq!(kvm_state.priority_add, 0b00010000);
        assert_eq!(kvm_state.irq_base, 0b00100000);
        assert_eq!(kvm_state.read_reg_select, 0);
        assert_eq!(kvm_state.poll, 1);
        assert_eq!(kvm_state.special_mask, 1);
        assert_eq!(kvm_state.init_state, 0b10);
        assert_eq!(kvm_state.auto_eoi, 1);
        assert_eq!(kvm_state.rotate_on_auto_eoi, 0);
        assert_eq!(kvm_state.special_fully_nested_mode, 1);
        assert_eq!(kvm_state.auto_eoi, 1);
        assert_eq!(kvm_state.elcr, 0b01000000);
        assert_eq!(kvm_state.elcr_mask, 0b10000000);

        let orig_state = PicState::from(&kvm_state);
        assert_eq!(state, orig_state);
    }

    #[test]
    fn ioapic_state() {
        let mut entry = IoapicRedirectionTableEntry::default();
        let noredir = IoapicRedirectionTableEntry::default();

        // default entry should be 0
        assert_eq!(entry.get(0, 64), 0);

        // set some values on our entry
        entry.set_vector(0b11111111);
        entry.set_delivery_mode(DeliveryMode::SMI);
        entry.set_dest_mode(DestinationMode::Physical);
        entry.set_delivery_status(DeliveryStatus::Pending);
        entry.set_polarity(1);
        entry.set_remote_irr(true);
        entry.set_trigger_mode(TriggerMode::Level);
        entry.set_interrupt_mask(true);
        entry.set_dest_id(0b10101010);

        // Bit repr as:  destid-reserved--------------------------------flags----vector--
        let bit_repr = 0b1010101000000000000000000000000000000000000000011111001011111111;
        // where flags is [interrupt_mask(1), trigger_mode(Level=1), remote_irr(1), polarity(1),
        //   delivery_status(Pending=1), dest_mode(Physical=0), delivery_mode(SMI=010)]

        assert_eq!(entry.get(0, 64), bit_repr);

        let mut state = IoapicState {
            base_address: 1,
            ioregsel: 2,
            ioapicid: 4,
            current_interrupt_level_bitmap: 8,
            redirect_table: [noredir; 120],
        };

        // Initialize first 24 (kvm_state limit) redirection entries
        for i in 0..24 {
            state.redirect_table[i] = entry;
        }

        let kvm_state = kvm_ioapic_state::from(&state);
        assert_eq!(kvm_state.base_address, 1);
        assert_eq!(kvm_state.ioregsel, 2);
        assert_eq!(kvm_state.id, 4);
        assert_eq!(kvm_state.irr, 8);
        assert_eq!(kvm_state.pad, 0);
        // check first 24 entries
        for i in 0..24 {
            assert_eq!(unsafe { kvm_state.redirtbl[i].bits }, bit_repr);
        }

        // compare with a conversion back
        assert_eq!(state, IoapicState::from(&kvm_state));
    }

    #[test]
    fn lapic_state() {
        let mut state = LapicState { regs: [0; 64] };
        // Apic id register, 4 bytes each with a different bit set
        state.regs[2] = 1 | 2 << 8 | 4 << 16 | 8 << 24;

        let kvm_state = kvm_lapic_state::from(&state);

        // check little endian bytes in kvm_state
        for i in 0..4 {
            assert_eq!(kvm_state.regs[32 + i] as u8, 2u8.pow(i as u32));
        }

        // Test converting back to a LapicState
        assert_eq!(state, LapicState::from(&kvm_state));
    }

    #[test]
    fn pit_state() {
        let channel = PitChannelState {
            count: 256,
            latched_count: 512,
            count_latched: PitRWState::LSB,
            status_latched: false,
            status: 7,
            read_state: PitRWState::MSB,
            write_state: PitRWState::Word1,
            reload_value: 8,
            rw_mode: PitRWMode::Both,
            mode: 5,
            bcd: false,
            gate: true,
            count_load_time: 1024,
        };

        let kvm_channel = kvm_pit_channel_state::from(&channel);

        // compare the various field translations
        assert_eq!(kvm_channel.count, 256);
        assert_eq!(kvm_channel.latched_count, 512);
        assert_eq!(kvm_channel.count_latched, 1);
        assert_eq!(kvm_channel.status_latched, 0);
        assert_eq!(kvm_channel.status, 7);
        assert_eq!(kvm_channel.read_state, 2);
        assert_eq!(kvm_channel.write_state, 4);
        assert_eq!(kvm_channel.write_latch, 8);
        assert_eq!(kvm_channel.rw_mode, 3);
        assert_eq!(kvm_channel.mode, 5);
        assert_eq!(kvm_channel.bcd, 0);
        assert_eq!(kvm_channel.gate, 1);
        assert_eq!(kvm_channel.count_load_time, 1024);

        // convert back and compare
        assert_eq!(channel, PitChannelState::from(&kvm_channel));

        // convert the full pitstate
        let state = PitState {
            channels: [channel, channel, channel],
            flags: 255,
        };
        let kvm_state = kvm_pit_state2::from(&state);

        assert_eq!(kvm_state.flags, 255);

        // compare a channel
        assert_eq!(channel, PitChannelState::from(&kvm_state.channels[0]));
        // convert back and compare
        assert_eq!(state, PitState::from(&kvm_state));
    }

    #[test]
    fn clock_handling() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        let mut clock_data = vm.get_pvclock().unwrap();
        clock_data.clock += 1000;
        vm.set_pvclock(&clock_data).unwrap();
    }

    #[test]
    fn set_gsi_routing() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        vm.create_irq_chip().unwrap();
        vm.set_gsi_routing(&[]).unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Ioapic,
                pin: 3,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[
            IrqRoute {
                gsi: 1,
                source: IrqSource::Irqchip {
                    chip: IrqSourceChip::Ioapic,
                    pin: 3,
                },
            },
            IrqRoute {
                gsi: 2,
                source: IrqSource::Msi {
                    address: 0xf000000,
                    data: 0xa0,
                },
            },
        ])
        .unwrap();
    }

    #[test]
    fn set_identity_map_addr() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        vm.set_identity_map_addr(GuestAddress(0x20000)).unwrap();
    }

    #[test]
    fn mp_state() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        vm.create_irq_chip().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let state = vcpu.get_mp_state().unwrap();
        vcpu.set_mp_state(&state).unwrap();
    }

    #[test]
    fn enable_feature() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        vm.create_irq_chip().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        unsafe { vcpu.enable_raw_capability(kvm_sys::KVM_CAP_HYPERV_SYNIC, &[0; 4]) }.unwrap();
    }

    #[test]
    fn from_fpu() {
        // Fpu has the largest arrays in our struct adapters.  Test that they're small enough for
        // Rust to copy.
        let mut fpu: Fpu = Default::default();
        let m = fpu.xmm.len();
        let n = fpu.xmm[0].len();
        fpu.xmm[m - 1][n - 1] = 42;

        let fpu = kvm_fpu::from(&fpu);
        assert_eq!(fpu.xmm.len(), m);
        assert_eq!(fpu.xmm[0].len(), n);
        assert_eq!(fpu.xmm[m - 1][n - 1], 42);
    }

    #[test]
    fn debugregs() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut dregs = vcpu.get_debugregs().unwrap();
        dregs.dr7 = 13;
        vcpu.set_debugregs(&dregs).unwrap();
        let dregs2 = vcpu.get_debugregs().unwrap();
        assert_eq!(dregs.dr7, dregs2.dr7);
    }

    #[test]
    fn xcrs() {
        let kvm = Kvm::new().unwrap();
        if !kvm.check_capability(HypervisorCap::Xcrs) {
            return;
        }

        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut xcrs = vcpu.get_xcrs().unwrap();
        xcrs[0].value = 1;
        vcpu.set_xcrs(&xcrs).unwrap();
        let xcrs2 = vcpu.get_xcrs().unwrap();
        assert_eq!(xcrs[0].value, xcrs2[0].value);
    }

    #[test]
    fn get_msrs() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut msrs = vec![
            // This one should succeed
            Register {
                id: 0x0000011e,
                ..Default::default()
            },
            // This one will fail to fetch
            Register {
                id: 0x000003f1,
                ..Default::default()
            },
        ];
        vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(msrs.len(), 1);
    }

    #[test]
    fn set_msrs() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        const MSR_TSC_AUX: u32 = 0xc0000103;
        let mut msrs = vec![Register {
            id: MSR_TSC_AUX,
            value: 42,
        }];
        vcpu.set_msrs(&msrs).unwrap();

        msrs[0].value = 0;
        vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(msrs.len(), 1);
        assert_eq!(msrs[0].id, MSR_TSC_AUX);
        assert_eq!(msrs[0].value, 42);
    }

    #[test]
    fn get_hyperv_cpuid() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm, ProtectionType::Unprotected).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let cpuid = vcpu.get_hyperv_cpuid();
        // Older kernels don't support so tolerate this kind of failure.
        match cpuid {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(e.errno(), EINVAL);
            }
        }
    }
}
