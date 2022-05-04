// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Defines Windows-specific submodules of sys_util

// Modules ported to windows
pub mod file_traits;
pub mod syslog;

mod platform_timer_utils;
pub use platform_timer_utils::*;

mod file_util;
pub use file_util::*;

use super::{errno_result, pid_t, Error, Result};
use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, SafeDescriptor};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    ptr::null_mut,
    sync::Once,
};
use winapi::{
    shared::{minwindef::DWORD, winerror::WAIT_TIMEOUT},
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        processthreadsapi::GetCurrentProcessId,
        synchapi::{CreateMutexA, ReleaseMutex, WaitForSingleObject},
        winbase::{INFINITE, WAIT_ABANDONED, WAIT_OBJECT_0},
        winuser::AllowSetForegroundWindow,
    },
};

#[inline(always)]
pub fn pagesize() -> usize {
    win_util::pagesize()
}

/// Cross-platform wrapper around getting the current process id.
#[inline(always)]
pub fn getpid() -> pid_t {
    // Safe because we only use the return value. ProcessId can safely be converted from DWORD to i32.
    unsafe { GetCurrentProcessId() as pid_t }
}

#[link(name = "stdio_fileno", kind = "static")]
extern "C" {
    fn stdout_fileno() -> i32;
    fn stderr_fileno() -> i32;
}

static mut STDOUT_FILENO: (Option<i32>, Once) = (None, Once::new());
static mut STDERR_FILENO: (Option<i32>, Once) = (None, Once::new());

pub fn get_stdout_fileno() -> i32 {
    // safe because use once to initialize this global structure and never write to it ever since
    unsafe {
        STDOUT_FILENO.1.call_once(|| {
            STDOUT_FILENO.0.replace(stdout_fileno());
        });
        STDOUT_FILENO.0.unwrap()
    }
}

pub fn get_stderr_fileno() -> i32 {
    // safe because use once to initialize this global structure and never write to it ever since
    unsafe {
        STDERR_FILENO.1.call_once(|| {
            STDERR_FILENO.0.replace(stderr_fileno());
        });
        STDERR_FILENO.0.unwrap()
    }
}

/// A Mutex (no data) that works across processes on Windows.
#[derive(Serialize, Deserialize, Debug)]
pub struct MultiProcessMutex {
    lock: SafeDescriptor,
}

impl MultiProcessMutex {
    pub fn new() -> Result<Self> {
        // Trivially safe (no memory passed, error checked).
        //
        // Note that we intentionally make this handle uninheritable by default via the mutex attrs.
        let lock_handle = unsafe {
            CreateMutexA(
                /* lpMutexAttributes= */ null_mut(),
                false as i32,
                null_mut(),
            )
        };

        if lock_handle == INVALID_HANDLE_VALUE {
            Err(Error::last())
        } else {
            Ok(Self {
                // Safe because the handle is valid & we own it exclusively.
                lock: unsafe { SafeDescriptor::from_raw_descriptor(lock_handle) },
            })
        }
    }

    /// Locks the mutex, returning a RAII guard similar to std::sync::Mutex.
    pub fn lock(&self) -> MultiProcessMutexGuard {
        if let Some(guard) = self.try_lock(INFINITE) {
            guard
        } else {
            // This should *never* happen.
            panic!("Timed out locking mutex with an infinite timeout. This should never happen.");
        }
    }

    /// Tries to lock the mutex, returning a RAII guard similar to std::sync::Mutex if we obtained
    /// the lock within the timeout.
    pub fn try_lock(&self, timeout_ms: u32) -> Option<MultiProcessMutexGuard> {
        // Safe because the mutex handle is guaranteed to exist.
        match unsafe { WaitForSingleObject(self.lock.as_raw_descriptor(), timeout_ms) } {
            WAIT_OBJECT_0 => Some(MultiProcessMutexGuard { lock: &self.lock }),
            WAIT_TIMEOUT => None,
            WAIT_ABANDONED => panic!(
                "The thread holding the mutex exited without releasing the mutex.\
                 Protected data may be corrupt."
            ),
            _ => {
                // This should *never* happen.
                panic!("Failed to lock mutex {:?}", Error::last())
            }
        }
    }

    /// Creates a new reference to the mutex.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            lock: self.lock.try_clone()?,
        })
    }
}

/// RAII guard for MultiProcessMutex.
pub struct MultiProcessMutexGuard<'a> {
    lock: &'a SafeDescriptor,
}

impl<'a> Drop for MultiProcessMutexGuard<'a> {
    fn drop(&mut self) {
        if unsafe { ReleaseMutex(self.lock.as_raw_descriptor()) } == 0 {
            panic!("Failed to unlock mutex: {:?}.", Error::last())
        }
    }
}

/// Open the file with the given path.
///
/// Note that on POSIX< this wrapper handles opening existing FDs via /proc/self/fd/N. On Windows,
/// this functionality doesn't exist, but we preserve this seemingly not very useful function to
/// simplify cross platform code.
pub fn open_file<P: AsRef<Path>>(path: P, options: &OpenOptions) -> Result<File> {
    Ok(options.open(path)?)
}

/// Grants the given process id temporary permission to foreground another window. This succeeds
/// only when the emulator is in the foreground, and will persist only until the next user
/// interaction with the window
pub fn give_foregrounding_permission(process_id: DWORD) -> Result<()> {
    // Safe because this API does not modify memory, and process_id remains in scope for
    // the duration of the call.
    match unsafe { AllowSetForegroundWindow(process_id) } {
        0 => errno_result(),
        _ => Ok(()),
    }
}
