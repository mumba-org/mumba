// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utility file for allocating exportable system memory.  On Linux systems,
//! this is is often done with memfd.

use base::SharedMemory;

use crate::rutabaga_gralloc::formats::canonical_image_requirements;
use crate::rutabaga_gralloc::gralloc::{Gralloc, ImageAllocationInfo, ImageMemoryRequirements};
use crate::rutabaga_utils::*;

/// A gralloc implementation capable of allocation from system memory.
pub struct SystemGralloc(());

impl SystemGralloc {
    fn new() -> Self {
        SystemGralloc(())
    }

    /// Returns a new `SystemGralloc` instance.
    pub fn init() -> RutabagaResult<Box<dyn Gralloc>> {
        Ok(Box::new(SystemGralloc::new()))
    }
}

impl Gralloc for SystemGralloc {
    fn supports_external_gpu_memory(&self) -> bool {
        false
    }

    fn supports_dmabuf(&self) -> bool {
        false
    }

    fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements> {
        let mut reqs = canonical_image_requirements(info)?;
        reqs.map_info = RUTABAGA_MAP_CACHE_CACHED;
        Ok(reqs)
    }

    fn allocate_memory(&mut self, reqs: ImageMemoryRequirements) -> RutabagaResult<RutabagaHandle> {
        let shm = SharedMemory::named("rutabaga_gralloc", reqs.size)?;
        Ok(RutabagaHandle {
            os_handle: shm.into(),
            handle_type: RUTABAGA_MEM_HANDLE_TYPE_SHM,
        })
    }
}
