// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use arch::fdt::{Error, FdtWriter, Result};
use arch::SERIAL_ADDR;
use devices::{PciAddress, PciInterruptPin};
use hypervisor::{PsciVersion, PSCI_0_2, PSCI_1_0};
use vm_memory::{GuestAddress, GuestMemory};

// This is the start of DRAM in the physical address space.
use crate::AARCH64_PHYS_MEM_START;

// These are GIC address-space location constants.
use crate::AARCH64_GIC_CPUI_BASE;
use crate::AARCH64_GIC_CPUI_SIZE;
use crate::AARCH64_GIC_DIST_BASE;
use crate::AARCH64_GIC_DIST_SIZE;
use crate::AARCH64_GIC_REDIST_SIZE;

// These are RTC related constants
use crate::AARCH64_RTC_ADDR;
use crate::AARCH64_RTC_IRQ;
use crate::AARCH64_RTC_SIZE;
use devices::pl030::PL030_AMBA_ID;

// These are serial device related constants.
use crate::AARCH64_SERIAL_1_3_IRQ;
use crate::AARCH64_SERIAL_2_4_IRQ;
use crate::AARCH64_SERIAL_SIZE;
use crate::AARCH64_SERIAL_SPEED;

use crate::AARCH64_PMU_IRQ;

// This is an arbitrary number to specify the node for the GIC.
// If we had a more complex interrupt architecture, then we'd need an enum for
// these.
const PHANDLE_GIC: u32 = 1;
const PHANDLE_RESTRICTED_DMA_POOL: u32 = 2;

// CPUs are assigned phandles starting with this number.
const PHANDLE_CPU0: u32 = 0x100;

// These are specified by the Linux GIC bindings
const GIC_FDT_IRQ_NUM_CELLS: u32 = 3;
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;
const GIC_FDT_IRQ_PPI_CPU_SHIFT: u32 = 8;
const GIC_FDT_IRQ_PPI_CPU_MASK: u32 = 0xff << GIC_FDT_IRQ_PPI_CPU_SHIFT;
const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;
const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;
const IRQ_TYPE_LEVEL_LOW: u32 = 0x00000008;

fn create_memory_node(fdt: &mut FdtWriter, guest_mem: &GuestMemory) -> Result<()> {
    let mem_size = guest_mem.memory_size();
    let mem_reg_prop = [AARCH64_PHYS_MEM_START, mem_size];

    let memory_node = fdt.begin_node("memory")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &mem_reg_prop)?;
    fdt.end_node(memory_node)?;
    Ok(())
}

fn create_resv_memory_node(fdt: &mut FdtWriter, resv_size: Option<u64>) -> Result<Option<u32>> {
    if let Some(resv_size) = resv_size {
        let resv_memory_node = fdt.begin_node("reserved-memory")?;
        fdt.property_u32("#address-cells", 0x2)?;
        fdt.property_u32("#size-cells", 0x2)?;
        fdt.property_null("ranges")?;

        let restricted_dma_pool = fdt.begin_node("restricted_dma_reserved")?;
        fdt.property_u32("phandle", PHANDLE_RESTRICTED_DMA_POOL)?;
        fdt.property_string("compatible", "restricted-dma-pool")?;
        fdt.property_u64("size", resv_size)?;
        fdt.property_u64("alignment", base::pagesize() as u64)?;
        fdt.end_node(restricted_dma_pool)?;

        fdt.end_node(resv_memory_node)?;
        Ok(Some(PHANDLE_RESTRICTED_DMA_POOL))
    } else {
        Ok(None)
    }
}

fn create_cpu_nodes(
    fdt: &mut FdtWriter,
    num_cpus: u32,
    cpu_clusters: Vec<Vec<usize>>,
    cpu_capacity: BTreeMap<usize, u32>,
) -> Result<()> {
    let cpus_node = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x0)?;

    for cpu_id in 0..num_cpus {
        let cpu_name = format!("cpu@{:x}", cpu_id);
        let cpu_node = fdt.begin_node(&cpu_name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if num_cpus > 1 {
            fdt.property_string("enable-method", "psci")?;
        }
        fdt.property_u32("reg", cpu_id)?;
        fdt.property_u32("phandle", PHANDLE_CPU0 + cpu_id)?;

        if let Some(capacity) = cpu_capacity.get(&(cpu_id as usize)) {
            fdt.property_u32("capacity-dmips-mhz", *capacity)?;
        }

        fdt.end_node(cpu_node)?;
    }

    if !cpu_clusters.is_empty() {
        let cpu_map_node = fdt.begin_node("cpu-map")?;
        for (cluster_idx, cpus) in cpu_clusters.iter().enumerate() {
            let cluster_node = fdt.begin_node(&format!("cluster{}", cluster_idx))?;
            for (core_idx, cpu_id) in cpus.iter().enumerate() {
                let core_node = fdt.begin_node(&format!("core{}", core_idx))?;
                fdt.property_u32("cpu", PHANDLE_CPU0 + *cpu_id as u32)?;
                fdt.end_node(core_node)?;
            }
            fdt.end_node(cluster_node)?;
        }
        fdt.end_node(cpu_map_node)?;
    }

    fdt.end_node(cpus_node)?;
    Ok(())
}

fn create_gic_node(fdt: &mut FdtWriter, is_gicv3: bool, num_cpus: u64) -> Result<()> {
    let mut gic_reg_prop = [AARCH64_GIC_DIST_BASE, AARCH64_GIC_DIST_SIZE, 0, 0];

    let intc_node = fdt.begin_node("intc")?;
    if is_gicv3 {
        fdt.property_string("compatible", "arm,gic-v3")?;
        gic_reg_prop[2] = AARCH64_GIC_DIST_BASE - (AARCH64_GIC_REDIST_SIZE * num_cpus);
        gic_reg_prop[3] = AARCH64_GIC_REDIST_SIZE * num_cpus;
    } else {
        fdt.property_string("compatible", "arm,cortex-a15-gic")?;
        gic_reg_prop[2] = AARCH64_GIC_CPUI_BASE;
        gic_reg_prop[3] = AARCH64_GIC_CPUI_SIZE;
    }
    fdt.property_u32("#interrupt-cells", GIC_FDT_IRQ_NUM_CELLS)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_array_u64("reg", &gic_reg_prop)?;
    fdt.property_u32("phandle", PHANDLE_GIC)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.end_node(intc_node)?;

    Ok(())
}

fn create_timer_node(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
    // These are fixed interrupt numbers for the timer device.
    let irqs = [13, 14, 11, 10];
    let compatible = "arm,armv8-timer";
    let cpu_mask: u32 =
        (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;

    let mut timer_reg_cells = Vec::new();
    for &irq in &irqs {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(cpu_mask | IRQ_TYPE_LEVEL_LOW);
    }

    let timer_node = fdt.begin_node("timer")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_array_u32("interrupts", &timer_reg_cells)?;
    fdt.property_null("always-on")?;
    fdt.end_node(timer_node)?;

    Ok(())
}

fn create_pmu_node(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
    let compatible = "arm,armv8-pmuv3";
    let cpu_mask: u32 =
        (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;
    let irq = [
        GIC_FDT_IRQ_TYPE_PPI,
        AARCH64_PMU_IRQ,
        cpu_mask | IRQ_TYPE_LEVEL_HIGH,
    ];

    let pmu_node = fdt.begin_node("pmu")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(pmu_node)?;
    Ok(())
}

fn create_serial_node(fdt: &mut FdtWriter, addr: u64, irq: u32) -> Result<()> {
    let serial_reg_prop = [addr, AARCH64_SERIAL_SIZE];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, irq, IRQ_TYPE_EDGE_RISING];

    let serial_node = fdt.begin_node(&format!("U6_16550A@{:x}", addr))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &serial_reg_prop)?;
    fdt.property_u32("clock-frequency", AARCH64_SERIAL_SPEED)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;

    Ok(())
}

fn create_serial_nodes(fdt: &mut FdtWriter) -> Result<()> {
    // Note that SERIAL_ADDR contains the I/O port addresses conventionally used
    // for serial ports on x86. This uses the same addresses (but on the MMIO bus)
    // to simplify the shared serial code.
    create_serial_node(fdt, SERIAL_ADDR[0], AARCH64_SERIAL_1_3_IRQ)?;
    create_serial_node(fdt, SERIAL_ADDR[1], AARCH64_SERIAL_2_4_IRQ)?;
    create_serial_node(fdt, SERIAL_ADDR[2], AARCH64_SERIAL_1_3_IRQ)?;
    create_serial_node(fdt, SERIAL_ADDR[3], AARCH64_SERIAL_2_4_IRQ)?;

    Ok(())
}

fn psci_compatible(version: &PsciVersion) -> Vec<&str> {
    // The PSCI kernel driver only supports compatible strings for the following
    // backward-compatible versions.
    let supported = [(PSCI_1_0, "arm,psci-1.0"), (PSCI_0_2, "arm,psci-0.2")];

    let mut compatible: Vec<_> = supported
        .iter()
        .filter(|&(v, _)| *version >= *v)
        .map(|&(_, c)| c)
        .collect();

    // The PSCI kernel driver also supports PSCI v0.1, which is NOT forward-compatible.
    if compatible.is_empty() {
        compatible = vec!["arm,psci"];
    }

    compatible
}

fn create_psci_node(fdt: &mut FdtWriter, version: &PsciVersion) -> Result<()> {
    let compatible = psci_compatible(version);
    let psci_node = fdt.begin_node("psci")?;
    fdt.property_string_list("compatible", &compatible)?;
    // Only support aarch64 guest
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci_node)?;

    Ok(())
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: Option<(GuestAddress, usize)>,
) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_u32("linux,pci-probe-only", 1)?;
    fdt.property_string("bootargs", cmdline)?;
    // Used by android bootloader for boot console output
    fdt.property_string("stdout-path", &format!("/U6_16550A@{:x}", SERIAL_ADDR[0]))?;

    let mut random_file = File::open("/dev/urandom").map_err(Error::FdtIoError)?;
    let mut kaslr_seed_bytes = [0u8; 8];
    random_file
        .read_exact(&mut kaslr_seed_bytes)
        .map_err(Error::FdtIoError)?;
    let kaslr_seed = u64::from_le_bytes(kaslr_seed_bytes);
    fdt.property_u64("kaslr-seed", kaslr_seed)?;

    let mut rng_seed_bytes = [0u8; 256];
    random_file
        .read_exact(&mut rng_seed_bytes)
        .map_err(Error::FdtIoError)?;
    fdt.property("rng-seed", &rng_seed_bytes)?;

    if let Some((initrd_addr, initrd_size)) = initrd {
        let initrd_start = initrd_addr.offset() as u32;
        let initrd_end = initrd_start + initrd_size as u32;
        fdt.property_u32("linux,initrd-start", initrd_start)?;
        fdt.property_u32("linux,initrd-end", initrd_end)?;
    }
    fdt.end_node(chosen_node)?;

    Ok(())
}

/// PCI host controller address range.
///
/// This represents a single entry in the "ranges" property for a PCI host controller.
///
/// See [PCI Bus Binding to Open Firmware](https://www.openfirmware.info/data/docs/bus.pci.pdf)
/// and https://www.kernel.org/doc/Documentation/devicetree/bindings/pci/host-generic-pci.txt
/// for more information.
#[derive(Copy, Clone)]
pub struct PciRange {
    pub space: PciAddressSpace,
    pub bus_address: u64,
    pub cpu_physical_address: u64,
    pub size: u64,
    pub prefetchable: bool,
}

/// PCI address space.
#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum PciAddressSpace {
    /// PCI configuration space
    Configuration = 0b00,
    /// I/O space
    Io = 0b01,
    /// 32-bit memory space
    Memory = 0b10,
    /// 64-bit memory space
    Memory64 = 0b11,
}

/// Location of memory-mapped PCI configuration space.
#[derive(Copy, Clone)]
pub struct PciConfigRegion {
    /// Physical address of the base of the memory-mapped PCI configuration region.
    pub base: u64,
    /// Size of the PCI configuration region in bytes.
    pub size: u64,
}

fn create_pci_nodes(
    fdt: &mut FdtWriter,
    pci_irqs: Vec<(PciAddress, u32, PciInterruptPin)>,
    cfg: PciConfigRegion,
    ranges: &[PciRange],
    dma_pool_phandle: Option<u32>,
) -> Result<()> {
    // Add devicetree nodes describing a PCI generic host controller.
    // See Documentation/devicetree/bindings/pci/host-generic-pci.txt in the kernel
    // and "PCI Bus Binding to IEEE Std 1275-1994".
    let ranges: Vec<u32> = ranges
        .iter()
        .map(|r| {
            let ss = r.space as u32;
            let p = r.prefetchable as u32;
            [
                // BUS_ADDRESS(3) encoded as defined in OF PCI Bus Binding
                (ss << 24) | (p << 30),
                (r.bus_address >> 32) as u32,
                r.bus_address as u32,
                // CPU_PHYSICAL(2)
                (r.cpu_physical_address >> 32) as u32,
                r.cpu_physical_address as u32,
                // SIZE(2)
                (r.size >> 32) as u32,
                r.size as u32,
            ]
        })
        .flatten()
        .collect();

    let bus_range = [0, 0]; // Only bus 0
    let reg = [cfg.base, cfg.size];

    let mut interrupts: Vec<u32> = Vec::new();
    let mut masks: Vec<u32> = Vec::new();

    for (address, irq_num, irq_pin) in pci_irqs.iter() {
        // PCI_DEVICE(3)
        interrupts.push(address.to_config_address(0, 8));
        interrupts.push(0);
        interrupts.push(0);

        // INT#(1)
        interrupts.push(irq_pin.to_mask() + 1);

        // CONTROLLER(PHANDLE)
        interrupts.push(PHANDLE_GIC);
        interrupts.push(0);
        interrupts.push(0);

        // CONTROLLER_DATA(3)
        interrupts.push(GIC_FDT_IRQ_TYPE_SPI);
        interrupts.push(*irq_num);
        interrupts.push(IRQ_TYPE_LEVEL_HIGH);

        // PCI_DEVICE(3)
        masks.push(0xf800); // bits 11..15 (device)
        masks.push(0);
        masks.push(0);

        // INT#(1)
        masks.push(0x7); // allow INTA#-INTD# (1 | 2 | 3 | 4)
    }

    let pci_node = fdt.begin_node("pci")?;
    fdt.property_string("compatible", "pci-host-cam-generic")?;
    fdt.property_string("device_type", "pci")?;
    fdt.property_array_u32("ranges", &ranges)?;
    fdt.property_array_u32("bus-range", &bus_range)?;
    fdt.property_u32("#address-cells", 3)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_array_u64("reg", &reg)?;
    fdt.property_u32("#interrupt-cells", 1)?;
    fdt.property_array_u32("interrupt-map", &interrupts)?;
    fdt.property_array_u32("interrupt-map-mask", &masks)?;
    fdt.property_null("dma-coherent")?;
    if let Some(dma_pool_phandle) = dma_pool_phandle {
        fdt.property_u32("memory-region", dma_pool_phandle)?;
    }
    fdt.end_node(pci_node)?;

    Ok(())
}

fn create_rtc_node(fdt: &mut FdtWriter) -> Result<()> {
    // the kernel driver for pl030 really really wants a clock node
    // associated with an AMBA device or it will fail to probe, so we
    // need to make up a clock node to associate with the pl030 rtc
    // node and an associated handle with a unique phandle value.
    const CLK_PHANDLE: u32 = 24;
    let clock_node = fdt.begin_node("pclk@3M")?;
    fdt.property_u32("#clock-cells", 0)?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("clock-frequency", 3141592)?;
    fdt.property_u32("phandle", CLK_PHANDLE)?;
    fdt.end_node(clock_node)?;

    let rtc_name = format!("rtc@{:x}", AARCH64_RTC_ADDR);
    let reg = [AARCH64_RTC_ADDR, AARCH64_RTC_SIZE];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, AARCH64_RTC_IRQ, IRQ_TYPE_LEVEL_HIGH];

    let rtc_node = fdt.begin_node(&rtc_name)?;
    fdt.property_string("compatible", "arm,primecell")?;
    fdt.property_u32("arm,primecell-periphid", PL030_AMBA_ID)?;
    fdt.property_array_u64("reg", &reg)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_u32("clocks", CLK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc_node)?;
    Ok(())
}

/// Creates a flattened device tree containing all of the parameters for the
/// kernel and loads it into the guest memory at the specified offset.
///
/// # Arguments
///
/// * `fdt_max_size` - The amount of space reserved for the device tree
/// * `guest_mem` - The guest memory object
/// * `pci_irqs` - List of PCI device address to PCI interrupt number and pin mappings
/// * `pci_cfg` - Location of the memory-mapped PCI configuration space.
/// * `pci_ranges` - Memory ranges accessible via the PCI host controller.
/// * `num_cpus` - Number of virtual CPUs the guest will have
/// * `fdt_load_offset` - The offset into physical memory for the device tree
/// * `cmdline` - The kernel commandline
/// * `initrd` - An optional tuple of initrd guest physical address and size
/// * `android_fstab` - An optional file holding Android fstab entries
/// * `is_gicv3` - True if gicv3, false if v2
/// * `psci_version` - the current PSCI version
pub fn create_fdt(
    fdt_max_size: usize,
    guest_mem: &GuestMemory,
    pci_irqs: Vec<(PciAddress, u32, PciInterruptPin)>,
    pci_cfg: PciConfigRegion,
    pci_ranges: &[PciRange],
    num_cpus: u32,
    cpu_clusters: Vec<Vec<usize>>,
    cpu_capacity: BTreeMap<usize, u32>,
    fdt_load_offset: u64,
    cmdline: &str,
    initrd: Option<(GuestAddress, usize)>,
    android_fstab: Option<File>,
    is_gicv3: bool,
    use_pmu: bool,
    psci_version: PsciVersion,
    swiotlb: Option<u64>,
) -> Result<()> {
    let mut fdt = FdtWriter::new(&[]);

    // The whole thing is put into one giant node with some top level properties
    let root_node = fdt.begin_node("")?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("#address-cells", 0x2)?;
    fdt.property_u32("#size-cells", 0x2)?;
    if let Some(android_fstab) = android_fstab {
        arch::android::create_android_fdt(&mut fdt, android_fstab)?;
    }
    create_chosen_node(&mut fdt, cmdline, initrd)?;
    create_memory_node(&mut fdt, guest_mem)?;
    let dma_pool_phandle = create_resv_memory_node(&mut fdt, swiotlb)?;
    create_cpu_nodes(&mut fdt, num_cpus, cpu_clusters, cpu_capacity)?;
    create_gic_node(&mut fdt, is_gicv3, num_cpus as u64)?;
    create_timer_node(&mut fdt, num_cpus)?;
    if use_pmu {
        create_pmu_node(&mut fdt, num_cpus)?;
    }
    create_serial_nodes(&mut fdt)?;
    create_psci_node(&mut fdt, &psci_version)?;
    create_pci_nodes(&mut fdt, pci_irqs, pci_cfg, pci_ranges, dma_pool_phandle)?;
    create_rtc_node(&mut fdt)?;
    // End giant node
    fdt.end_node(root_node)?;

    let fdt_final = fdt.finish(fdt_max_size)?;

    let fdt_address = GuestAddress(AARCH64_PHYS_MEM_START + fdt_load_offset);
    let written = guest_mem
        .write_at_addr(fdt_final.as_slice(), fdt_address)
        .map_err(|_| Error::FdtGuestMemoryWriteError)?;
    if written < fdt_max_size {
        return Err(Error::FdtGuestMemoryWriteError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psci_compatible_v0_1() {
        assert_eq!(
            psci_compatible(&PsciVersion::new(0, 1).unwrap()),
            vec!["arm,psci"]
        );
    }

    #[test]
    fn psci_compatible_v0_2() {
        assert_eq!(
            psci_compatible(&PsciVersion::new(0, 2).unwrap()),
            vec!["arm,psci-0.2"]
        );
    }

    #[test]
    fn psci_compatible_v0_5() {
        // Only the 0.2 version supported by the kernel should be added.
        assert_eq!(
            psci_compatible(&PsciVersion::new(0, 5).unwrap()),
            vec!["arm,psci-0.2"]
        );
    }

    #[test]
    fn psci_compatible_v1_0() {
        // Both 1.0 and 0.2 should be listed, in that order.
        assert_eq!(
            psci_compatible(&PsciVersion::new(1, 0).unwrap()),
            vec!["arm,psci-1.0", "arm,psci-0.2"]
        );
    }

    #[test]
    fn psci_compatible_v1_5() {
        // Only the 1.0 and 0.2 versions supported by the kernel should be listed.
        assert_eq!(
            psci_compatible(&PsciVersion::new(1, 5).unwrap()),
            vec!["arm,psci-1.0", "arm,psci-0.2"]
        );
    }
}
