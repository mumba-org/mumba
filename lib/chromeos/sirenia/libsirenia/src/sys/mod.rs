// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides abstraction for needed libc functionality that isn't included in
//! sys_util. Generally Sirenia code outside of this module shouldn't directly
//! interact with the libc package.

use std::fs::File;
use std::io::{self, stdin, Write};
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;

use anyhow::Context;
use libc::{
    self, c_int, isatty, sigfillset, sigprocmask, sigset_t, wait, ECHILD, SIG_BLOCK, SIG_UNBLOCK,
};
use sys_util::{self, add_fd_flags, error, handle_eintr, PollContext, Terminal, WatchingEvents};

pub struct ScopedRaw {}

impl ScopedRaw {
    pub fn new() -> Result<Self, sys_util::Error> {
        stdin().set_raw_mode().map(|_| ScopedRaw {})
    }
}

impl Drop for ScopedRaw {
    fn drop(&mut self) {
        if let Err(err) = stdin().set_canon_mode() {
            error!("Failed exit raw stdin: {}", err);
        }
    }
}

pub fn errno() -> c_int {
    io::Error::last_os_error().raw_os_error().unwrap()
}

pub fn wait_for_child() -> bool {
    let mut ret: c_int = 0;
    // This is safe because it merely blocks execution until a process
    // life-cycle event occurs, or there are no child processes to wait on.
    if unsafe { wait(&mut ret) } == -1 && errno() == ECHILD {
        return false;
    }

    true
}

pub fn block_all_signals() {
    let mut signal_set: sigset_t;
    // This is safe as long as nothing else is depending on receiving a signal
    // to guarantee safety.
    unsafe {
        signal_set = MaybeUninit::zeroed().assume_init();
        // Block signals since init should not die or return.
        sigfillset(&mut signal_set);
        sigprocmask(SIG_BLOCK, &signal_set, null_mut());
    }
}

pub fn unblock_all_signals() {
    let mut signal_set: sigset_t;
    // This is safe because it doesn't allocate or free any structures.
    unsafe {
        signal_set = MaybeUninit::zeroed().assume_init();
        // Block signals since init should not die or return.
        sigfillset(&mut signal_set);
        sigprocmask(SIG_UNBLOCK, &signal_set, null_mut());
    }
}

/// Forks the process and returns the child pid or 0 for the child process.
///
/// # Safety
///
/// This is only safe if the open file descriptors are intended to be cloned
/// into the child process. The child should explicitly close any file
/// descriptors that are not intended to be kept open.
pub unsafe fn fork() -> Result<i32, io::Error> {
    // Safe if the conditions for calling the outer function are met.
    let ret: c_int = unsafe { libc::fork() };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Light wrapper over the dup syscall.
///
/// Provides safety by ensuring the resulting file descriptor is owned.
pub fn dup<F: FromRawFd>(fd: RawFd) -> Result<F, io::Error> {
    // Safe because this doesn't modify any memory and we check the return value
    // and take ownership of the resulting file descriptor in an `F`.
    let dup_fd: c_int = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { F::from_raw_fd(dup_fd as RawFd) })
}

pub fn is_a_tty(fd: RawFd) -> bool {
    // This is trivially safe.
    unsafe { isatty(fd) != 0 }
}

pub fn get_a_pty() -> Result<(File, File), anyhow::Error> {
    let main: RawFd = unsafe { libc::getpt() };
    if main < 0 {
        Err(io::Error::last_os_error()).context("bad pty")?;
    }

    let main = unsafe { File::from_raw_fd(main) };

    if unsafe { libc::grantpt(main.as_raw_fd()) } < 0 {
        Err(io::Error::last_os_error()).context("grantpt")?;
    }

    if unsafe { libc::unlockpt(main.as_raw_fd()) } < 0 {
        Err(io::Error::last_os_error()).context("unlockpt")?;
    }

    let name = unsafe { libc::ptsname(main.as_raw_fd()) };
    if name.is_null() {
        Err(io::Error::last_os_error()).context("ptsname")?;
    }

    let client: RawFd = unsafe { libc::open(name, libc::O_RDWR) };
    if client < 0 {
        Err(io::Error::last_os_error()).context("failed to open pty client")?;
    }
    let client = unsafe { File::from_raw_fd(client) };
    Ok((main, client))
}

/// Halts the system.
pub fn halt() -> Result<(), io::Error> {
    // Safe because sync is called prior to reboot and the error code is checked.
    let ret: c_int = unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_HALT)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // This should never happen.
        Ok(())
    }
}

/// Reboots the system.
pub fn power_off() -> Result<(), io::Error> {
    // Safe because sync is called prior to reboot and the error code is checked.
    let ret: c_int = unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // This should never happen.
        Ok(())
    }
}

/// Powers off the system.
pub fn reboot() -> Result<(), io::Error> {
    // Safe because sync is called prior to reboot and the error code is checked.
    let ret: c_int = unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_RESTART)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // This should never happen.
        Ok(())
    }
}

pub fn set_nonblocking(fd: RawFd) -> Result<(), sys_util::Error> {
    add_fd_flags(fd, libc::O_NONBLOCK)
}

pub fn eagain_is_ok<T>(ret: Result<T, io::Error>) -> Result<Option<T>, io::Error> {
    Ok(match ret {
        Ok(v) => Some(v),
        Err(err) => {
            if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                None
            } else {
                return Err(err);
            }
        }
    })
}

pub fn write_all_blocking<W: Write + AsRawFd>(write: &mut W, buf: &[u8]) -> Result<(), io::Error> {
    let mut poll: Option<PollContext<()>> = None;
    let mut offset = 0usize;
    while offset < buf.len() {
        match handle_eintr!(write.write(&buf[offset..])) {
            Ok(written) => {
                offset += written;
            }
            Err(err) => {
                if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                    // Lazy initialization is used to avoid getting a poll fd if it is not needed.
                    let poll = match &mut poll {
                        Some(p) => p,
                        None => {
                            let p = PollContext::new()?;
                            let events = WatchingEvents::empty().set_write();
                            p.add_fd_with_events(write, events, ())?;
                            poll = Some(p);
                            poll.as_mut().unwrap()
                        }
                    };
                    poll.wait()?;
                } else {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}
