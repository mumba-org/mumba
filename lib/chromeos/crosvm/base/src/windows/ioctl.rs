// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros and wrapper functions for dealing with ioctls.

use std::os::raw::*;

use crate::descriptor::AsRawDescriptor;

/// Raw macro to declare the expression that calculates an ioctl number
#[macro_export]
macro_rules! ioctl_expr {
    ($dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        (($dir << $crate::platform::ioctl::_IOC_DIRSHIFT)
            | ($ty << $crate::platform::ioctl::_IOC_TYPESHIFT)
            | ($nr << $crate::platform::ioctl::_IOC_NRSHIFT)
            | ($size << $crate::platform::ioctl::_IOC_SIZESHIFT)) as $crate::platform::IoctlNr
    };
}

/// Raw macro to declare a function that returns an ioctl number.
#[macro_export]
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        #[allow(non_snake_case)]
        pub const fn $name() -> $crate::platform::IoctlNr {
            $crate::ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        pub const fn $name($($v: ::std::os::raw::c_uint),+) -> $crate::platform::IoctlNr {
            $crate::ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
}

/// Declare an ioctl that transfers no data.
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        $crate::ioctl_ioc_nr!($name, $crate::platform::ioctl::_IOC_NONE, $ty, $nr, 0);
    };
    ($name:ident, $ty:expr, $nr:expr, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!($name, $crate::platform::ioctl::_IOC_NONE, $ty, $nr, 0, $($v),+);
    };
}

/// Declare an ioctl that reads data.
#[macro_export]
macro_rules! ioctl_ior_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $crate::platform::ioctl::_IOC_READ,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $crate::platform::ioctl::_IOC_READ,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}

/// Declare an ioctl that writes data.
#[macro_export]
macro_rules! ioctl_iow_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $crate::platform::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $crate::platform::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}

/// Declare an ioctl that reads and writes data.
#[macro_export]
macro_rules! ioctl_iowr_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $crate::platform::ioctl::_IOC_READ | $crate::platform::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $crate::platform::ioctl::_IOC_READ | $crate::platform::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}

pub const _IOC_NRBITS: c_uint = 8;
pub const _IOC_TYPEBITS: c_uint = 8;
pub const _IOC_SIZEBITS: c_uint = 14;
pub const _IOC_DIRBITS: c_uint = 2;
pub const _IOC_NRMASK: c_uint = 255;
pub const _IOC_TYPEMASK: c_uint = 255;
pub const _IOC_SIZEMASK: c_uint = 16383;
pub const _IOC_DIRMASK: c_uint = 3;
pub const _IOC_NRSHIFT: c_uint = 0;
pub const _IOC_TYPESHIFT: c_uint = 8;
pub const _IOC_SIZESHIFT: c_uint = 16;
pub const _IOC_DIRSHIFT: c_uint = 30;
pub const _IOC_NONE: c_uint = 0;
pub const _IOC_WRITE: c_uint = 1;
pub const _IOC_READ: c_uint = 2;
pub const IOC_IN: c_uint = 1_073_741_824;
pub const IOC_OUT: c_uint = 2_147_483_648;
pub const IOC_INOUT: c_uint = 3_221_225_472;
pub const IOCSIZE_MASK: c_uint = 1_073_676_288;
pub const IOCSIZE_SHIFT: c_uint = 16;

/// Run an ioctl with no arguments.
/// # Safety
/// 1. descriptor must be an open FD.
pub unsafe fn ioctl<F: AsRawDescriptor>(descriptor: &F, nr: IoctlNr) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, 0)
}

/// Run an ioctl with a single value argument.
/// # Safety
/// 1. descriptor must be an open FD.
/// 2. the ioctl expects a value as its argument, and not a pointer.
pub unsafe fn ioctl_with_val<F: AsRawDescriptor>(
    descriptor: &F,
    nr: IoctlNr,
    arg: c_ulong,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
}

/// Run an ioctl with an immutable reference.
/// # Safety
/// 1. descriptor must be an open FD.
/// 2. the memory provided by arg is of the expected size for the ioctl.
pub unsafe fn ioctl_with_ref<F: AsRawDescriptor, T>(descriptor: &F, nr: IoctlNr, arg: &T) -> c_int {
    libc::ioctl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *const T as *const c_void,
    )
}

/// Run an ioctl with a mutable reference.
/// # Safety
/// 1. descriptor must be an open FD.
/// 2. the memory provided by arg is of the expected size for the ioctl.
pub unsafe fn ioctl_with_mut_ref<F: AsRawDescriptor, T>(
    descriptor: &F,
    nr: IoctlNr,
    arg: &mut T,
) -> c_int {
    libc::ioctl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *mut T as *mut c_void,
    )
}

/// Run an ioctl with a raw pointer.
/// # Safety
/// 1. descriptor must be an open FD.
/// 2. arg points to valid memory set up as expected by the ioctl.
pub unsafe fn ioctl_with_ptr<F: AsRawDescriptor, T>(
    descriptor: &F,
    nr: IoctlNr,
    arg: *const T,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *const c_void)
}

/// Run an ioctl with a raw pointer, specifying the size of the buffer.
/// # Safety
/// 1. descriptor must be an open FD.
/// 2. arg points to valid memory set up as expected by the ioctl.
pub unsafe fn ioctl_with_ptr_sized<F: AsRawDescriptor, T>(
    handle: &F,
    nr: IoctlNr,
    arg: *const T,
    _size: usize,
) -> c_int {
    ioctl_with_ptr(handle, nr, arg)
}

/// Run an ioctl with a mutable raw pointer.
/// # Safety
/// 1. descriptor must be an open FD.
/// 2. arg points to valid memory set up as expected by the ioctl.
pub unsafe fn ioctl_with_mut_ptr<F: AsRawDescriptor, T>(
    descriptor: &F,
    nr: IoctlNr,
    arg: *mut T,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *mut c_void)
}

#[cfg(test)]
mod tests {
    const TUNTAP: ::std::os::raw::c_uint = 0x54;
    const VHOST: ::std::os::raw::c_uint = 0xaf;
    const EVDEV: ::std::os::raw::c_uint = 0x45;

    ioctl_io_nr!(VHOST_SET_OWNER, VHOST, 0x01);
    ioctl_ior_nr!(TUNGETFEATURES, TUNTAP, 0xcf, ::std::os::raw::c_uint);
    ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 0xd9, ::std::os::raw::c_int);
    ioctl_iowr_nr!(VHOST_GET_VRING_BASE, VHOST, 0x12, ::std::os::raw::c_int);

    ioctl_ior_nr!(EVIOCGBIT, EVDEV, 0x20 + evt, [u8; 128], evt);
    ioctl_io_nr!(FAKE_IOCTL_2_ARG, EVDEV, 0x01 + x + y, x, y);

    #[test]
    fn ioctl_macros() {
        assert_eq!(0x0000af01, VHOST_SET_OWNER());
        assert_eq!(0x800454cf, TUNGETFEATURES());
        assert_eq!(0x400454d9, TUNSETQUEUE());
        assert_eq!(0xc004af12, VHOST_GET_VRING_BASE());

        assert_eq!(0x80804522, EVIOCGBIT(2));
        assert_eq!(0x00004509, FAKE_IOCTL_2_ARG(3, 5));
    }
}
