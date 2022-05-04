// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod alloc;
pub mod descriptor;
pub mod descriptor_reflection;
mod errno;
pub mod external_mapping;
pub mod scoped_event_macro;
mod tube;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

pub use alloc::LayoutAllocation;
pub use errno::{errno_result, Error, Result};
pub use external_mapping::{Error as ExternalMappingError, Result as ExternalMappingResult, *};
pub use scoped_event_macro::*;
pub use tube::{Error as TubeError, RecvTube, Result as TubeResult, SendTube, Tube};

cfg_if::cfg_if! {
     if #[cfg(unix)] {
        mod event;
        mod ioctl;
        mod mmap;
        mod notifiers;
        mod shm;
        mod timer;
        mod wait_context;

        pub use unix as platform;

        pub use unix::net::*;
        pub use unix::ioctl::*;

        pub use event::{Event, EventReadResult, ScopedEvent};
        pub use crate::ioctl::{
            ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
        };
        pub use mmap::{
            MemoryMapping, MemoryMappingBuilder, MemoryMappingBuilderUnix, Unix as MemoryMappingUnix,
        };
        pub use notifiers::*;
        pub use shm::{SharedMemory, Unix as SharedMemoryUnix};
        pub use timer::{FakeTimer, Timer};
        pub use wait_context::{EventToken, EventType, TriggeredEvent, WaitContext};
     } else if #[cfg(windows)] {
        pub use windows as platform;
        pub use tube::{set_duplicate_handle_tube, set_alias_pid, DuplicateHandleTube};
     } else {
        compile_error!("Unsupported platform");
     }
}

pub use crate::descriptor::{
    AsRawDescriptor, Descriptor, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor,
};
pub use platform::*;

/// Wraps an AsRawDescriptor in the simple Descriptor struct, which
/// has AsRawFd methods for interfacing with sys_util
pub fn wrap_descriptor(descriptor: &dyn AsRawDescriptor) -> Descriptor {
    Descriptor(descriptor.as_raw_descriptor())
}

/// Verifies that |raw_descriptor| is actually owned by this process and duplicates it
/// to ensure that we have a unique handle to it.
#[cfg(unix)]
pub fn validate_raw_descriptor(raw_descriptor: RawDescriptor) -> Result<RawDescriptor> {
    validate_raw_fd(raw_descriptor)
}

/// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
pub trait AsRawDescriptors {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor>;
}

impl<T> AsRawDescriptors for T
where
    T: AsRawDescriptor,
{
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![self.as_raw_descriptor()]
    }
}
