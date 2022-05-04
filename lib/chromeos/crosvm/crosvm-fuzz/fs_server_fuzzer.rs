// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

#[cfg(fuzzing)]
mod fs_server_fuzzer {
    use std::convert::TryInto;

    use cros_fuzz::fuzz_target;
    use devices::virtio::{create_descriptor_chain, DescriptorType, Reader, Writer};
    use fuse::fuzzing::fuzz_server;
    use vm_memory::{GuestAddress, GuestMemory};

    const MEM_SIZE: u64 = 256 * 1024 * 1024;
    const BUFFER_ADDR: GuestAddress = GuestAddress(0x100);

    thread_local! {
        static GUEST_MEM: GuestMemory = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    }

    fuzz_target!(|data| {
        use DescriptorType::*;

        GUEST_MEM.with(|mem| {
            mem.write_all_at_addr(data, BUFFER_ADDR).unwrap();

            let chain = create_descriptor_chain(
                mem,
                GuestAddress(0),
                BUFFER_ADDR,
                vec![
                    (Readable, data.len().try_into().unwrap()),
                    (
                        Writable,
                        (MEM_SIZE as u32)
                            .saturating_sub(data.len().try_into().unwrap())
                            .saturating_sub(0x100),
                    ),
                ],
                0,
            )
            .unwrap();

            let r = Reader::new(mem.clone(), chain.clone()).unwrap();
            let w = Writer::new(mem.clone(), chain).unwrap();
            fuzz_server(r, w);
        });
    });
}
