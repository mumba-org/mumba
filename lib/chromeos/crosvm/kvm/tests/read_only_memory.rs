// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use base::{MemoryMappingBuilder, SharedMemory};
use kvm::*;
use kvm_sys::kvm_regs;
use vm_memory::{GuestAddress, GuestMemory};

#[test]
fn test_run() {
    /*
    0000  268A07  mov al,[es:bx]
    0003  0401    add al,0x1
    0005  268807  mov [es:bx],al
    0008  F4      hlt
    */
    let code = [0x26, 0x8a, 0x07, 0x04, 0x01, 0x26, 0x88, 0x07, 0xf4];
    let mem_size = 0x2000;
    let load_addr = GuestAddress(0x1000);
    let guest_mem = GuestMemory::new(&[]).unwrap();
    let mem = SharedMemory::anon(mem_size).expect("failed to create shared memory");
    let mmap = MemoryMappingBuilder::new(mem_size as usize)
        .from_shared_memory(&mem)
        .build()
        .expect("failed to create memory mapping");

    mmap.write_slice(&code[..], load_addr.offset() as usize)
        .expect("Writing code to memory failed.");

    let kvm = Kvm::new().expect("new kvm failed");
    let mut vm = Vm::new(&kvm, guest_mem).expect("new vm failed");
    let vcpu = Vcpu::new(0, &kvm, &vm).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_sregs.es.base = 0x3000;
    vcpu_sregs.es.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs: kvm_regs = unsafe { std::mem::zeroed() };
    vcpu_regs.rip = load_addr.offset() as u64;
    vcpu_regs.rflags = 2;
    vcpu_regs.rax = 0x66;
    vcpu_regs.rbx = 0;
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");
    vm.add_memory_region(
        GuestAddress(0),
        Box::new(
            MemoryMappingBuilder::new(mem_size as usize)
                .from_shared_memory(&mem)
                .build()
                .expect("failed to create memory mapping"),
        ),
        false,
        false,
    )
    .expect("failed to register memory");

    // Give some read only memory for the test code to read from and force a vcpu exit when it reads
    // from it.
    let mem_ro = SharedMemory::anon(0x1000).expect("failed to create shared memory");
    let mmap_ro = MemoryMappingBuilder::new(0x1000)
        .from_shared_memory(&mem_ro)
        .build()
        .expect("failed to create memory mapping");
    mmap_ro
        .write_obj(vcpu_regs.rax as u8, 0)
        .expect("failed writing data to ro memory");
    vm.add_memory_region(
        GuestAddress(vcpu_sregs.es.base),
        Box::new(
            MemoryMappingBuilder::new(0x1000)
                .from_shared_memory(&mem_ro)
                .build()
                .expect("failed to create memory mapping"),
        ),
        true,
        false,
    )
    .expect("failed to register memory");

    // Ensure we get exactly 1 exit from attempting to write to read only memory.
    let mut exits = 0;

    let runnable_vcpu = vcpu.to_runnable(None).unwrap();
    loop {
        match runnable_vcpu.run().expect("run failed") {
            VcpuExit::Hlt => break,
            VcpuExit::MmioWrite {
                address,
                size: 1,
                data,
            } => {
                assert_eq!(address, vcpu_sregs.es.base);
                assert_eq!(data[0] as u64, vcpu_regs.rax + 1);
                exits += 1;
            }
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    // Check that exactly 1 attempt to write to read only memory was made, and that the memory is
    // unchanged after that attempt.
    assert_eq!(exits, 1);
    assert_eq!(
        mmap_ro
            .read_obj::<u8>(0)
            .expect("failed to read data from ro memory"),
        vcpu_regs.rax as u8
    );
}
