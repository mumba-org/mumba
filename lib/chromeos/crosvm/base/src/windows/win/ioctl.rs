// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros and wrapper functions for dealing with ioctls.

use std::{mem::size_of, os::raw::*, ptr::null_mut};

use crate::descriptor::AsRawDescriptor;
pub use winapi::um::winioctl::{CTL_CODE, FILE_ANY_ACCESS, METHOD_BUFFERED};
use winapi::um::{errhandlingapi::GetLastError, ioapiset::DeviceIoControl};

/// Raw macro to declare the expression that calculates an ioctl number
#[macro_export]
macro_rules! device_io_control_expr {
    // TODO (colindr) b/144440409: right now GVM is our only DeviceIOControl
    //  target on windows, and it only uses METHOD_BUFFERED for the transfer
    //  type and FILE_ANY_ACCESS for the required access, so we're going to
    //  just use that for now. However, we may need to support more
    //  options later.
    ($dtype:expr, $code:expr) => {
        $crate::platform::CTL_CODE(
            $dtype,
            $code,
            $crate::platform::METHOD_BUFFERED,
            $crate::platform::FILE_ANY_ACCESS,
        ) as ::std::os::raw::c_ulong
    };
}

/// Raw macro to declare a function that returns an DeviceIOControl code.
#[macro_export]
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dtype:expr, $code:expr) => {
        #[allow(non_snake_case)]
        pub fn $name() -> ::std::os::raw::c_ulong {
            $crate::device_io_control_expr!($dtype, $code)
        }
    };
    ($name:ident, $dtype:expr, $code:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        pub fn $name($($v: ::std::os::raw::c_uint),+) -> ::std::os::raw::c_ulong {
            $crate::device_io_control_expr!($dtype, $code)
        }
    };
}

/// Declare an ioctl that transfers no data.
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        $crate::ioctl_ioc_nr!($name, $ty, $nr);
    };
    ($name:ident, $ty:expr, $nr:expr, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!($name, $ty, $nr, $($v),+);
    };
}

/// Declare an ioctl that reads data.
#[macro_export]
macro_rules! ioctl_ior_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr,
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
            $ty,
            $nr
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr,
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
            $ty,
            $nr
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!(
            $name,
            $ty,
            $nr,
            $($v),+
        );
    };
}

pub type IoctlNr = c_ulong;

/// Run an ioctl with no arguments.
// (colindr) b/144457461 : This will probably not be used on windows.
// It's only used on linux for the ioctls that override the exit code to
// be the  return value of the ioctl. As far as I can tell, no DeviceIoControl
// will do this, they will always instead return values in the output
// buffer. So, as a result, we have no tests for this function, and
// we may want to remove it if we never use it on windows, but we can't
// remove it right now until we re-implement all the code that calls
// this funciton for windows.
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking.
pub unsafe fn ioctl<F: AsRawDescriptor>(handle: &F, nr: IoctlNr) -> c_int {
    let mut byte_ret: c_ulong = 0;
    let ret = DeviceIoControl(
        handle.as_raw_descriptor(),
        nr,
        null_mut(),
        0,
        null_mut(),
        0,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run an ioctl with a single value argument
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking.
pub unsafe fn ioctl_with_val(handle: &dyn AsRawDescriptor, nr: IoctlNr, mut arg: c_ulong) -> c_int {
    let mut byte_ret: c_ulong = 0;

    let ret = DeviceIoControl(
        handle.as_raw_descriptor(),
        nr,
        &mut arg as *mut c_ulong as *mut c_void,
        size_of::<c_ulong>() as u32,
        null_mut(),
        0,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run an ioctl with an immutable reference.
/// # Safety
/// Look at `ioctl_with_ptr` comments.
pub unsafe fn ioctl_with_ref<T>(handle: &dyn AsRawDescriptor, nr: IoctlNr, arg: &T) -> c_int {
    ioctl_with_ptr(handle, nr, arg)
}

/// Run an ioctl with a mutable reference.
/// # Safety
/// Look at `ioctl_with_ptr` comments.
pub unsafe fn ioctl_with_mut_ref<T>(
    handle: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: &mut T,
) -> c_int {
    ioctl_with_mut_ptr(handle, nr, arg)
}

/// Run an ioctl with a raw pointer, specifying the size of the buffer.
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking. Also The caller should make sure `T` is valid.
pub unsafe fn ioctl_with_ptr_sized<T>(
    handle: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *const T,
    size: usize,
) -> c_int {
    let mut byte_ret: c_ulong = 0;

    // We are trusting the DeviceIoControl function to not write anything
    // to the input buffer. Just because it's a *const does not prevent
    // the unsafe call from writing to it.
    let ret = DeviceIoControl(
        handle.as_raw_descriptor(),
        nr,
        arg as *mut c_void,
        size as u32,
        // We pass a null_mut as the output buffer.  If you expect
        // an output, you should be calling the mut variant of this
        // function.
        null_mut(),
        0,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run an ioctl with a raw pointer.
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking. Also The caller should make sure `T` is valid.
pub unsafe fn ioctl_with_ptr<T>(handle: &dyn AsRawDescriptor, nr: IoctlNr, arg: *const T) -> c_int {
    ioctl_with_ptr_sized(handle, nr, arg, size_of::<T>())
}

/// Run an ioctl with a mutable raw pointer.
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// and it does size checking. Also The caller should make sure `T` is valid.
pub unsafe fn ioctl_with_mut_ptr<T>(
    handle: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *mut T,
) -> c_int {
    let mut byte_ret: c_ulong = 0;

    let ret = DeviceIoControl(
        handle.as_raw_descriptor(),
        nr,
        arg as *mut c_void,
        size_of::<T>() as u32,
        arg as *mut c_void,
        size_of::<T>() as u32,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

/// Run a DeviceIoControl, specifying all options, only available on windows
/// # Safety
/// This method should be safe as `DeviceIoControl` will handle error cases
/// for invalid paramters and takes input buffer and output buffer size
/// arguments. Also The caller should make sure `T` is valid.
pub unsafe fn device_io_control<F: AsRawDescriptor, T, T2>(
    handle: &F,
    nr: IoctlNr,
    input: &T,
    inputsize: u32,
    output: &mut T2,
    outputsize: u32,
) -> c_int {
    let mut byte_ret: c_ulong = 0;

    let ret = DeviceIoControl(
        handle.as_raw_descriptor(),
        nr,
        input as *const T as *mut c_void,
        inputsize,
        output as *mut T2 as *mut c_void,
        outputsize,
        &mut byte_ret,
        null_mut(),
    );

    if ret == 1 {
        return 0;
    }

    GetLastError() as i32
}

#[cfg(test)]
mod tests {

    use winapi::um::winioctl::{FSCTL_GET_COMPRESSION, FSCTL_SET_COMPRESSION};

    use winapi::um::{
        fileapi::{CreateFileW, OPEN_EXISTING},
        winbase::SECURITY_SQOS_PRESENT,
        winnt::{
            COMPRESSION_FORMAT_LZNT1, COMPRESSION_FORMAT_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            GENERIC_READ, GENERIC_WRITE,
        },
    };

    use std::{fs::OpenOptions, os::raw::*, ptr::null_mut};

    use std::{ffi::OsStr, fs::File, io::prelude::*, os::windows::ffi::OsStrExt};

    use std::os::windows::prelude::*;

    use tempfile::tempdir;

    // helper func, returns str as Vec<u16>
    fn to_u16s<S: AsRef<OsStr>>(s: S) -> std::io::Result<Vec<u16>> {
        Ok(s.as_ref().encode_wide().chain(Some(0)).collect())
    }

    #[test]
    fn ioct_get_and_set_compression() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.dat");
        let file_path = file_path.as_path();

        // compressed = empty short for compressed status to be read into
        let mut compressed: c_ushort = 0x0000;

        // open our random file and write "foo" in it
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path)
            .unwrap();
        f.write_all(b"foo").expect("Failed to write bytes.");
        f.sync_all().expect("Failed to sync all.");

        // read the compression status
        let ecode = unsafe {
            super::super::ioctl::ioctl_with_mut_ref(&f, FSCTL_GET_COMPRESSION, &mut compressed)
        };

        // shouldn't error
        assert_eq!(ecode, 0);
        // should not be compressed by default (not sure if this will be the case on
        // all machines...)
        assert_eq!(compressed, COMPRESSION_FORMAT_NONE);

        // Now do a FSCTL_SET_COMPRESSED to set it to COMPRESSION_FORMAT_LZNT1.
        compressed = COMPRESSION_FORMAT_LZNT1;

        // NOTE: Theoretically I should be able to open this file like so:
        // let mut f = OpenOptions::new()
        //     .access_mode(GENERIC_WRITE|GENERIC_WRITE)
        //     .share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE)
        //     .open("test.dat").unwrap();
        //
        //   However, that does not work, and I'm not sure why.  Here's where
        //   the underlying std code is doing a CreateFileW:
        //   https://github.com/rust-lang/rust/blob/master/src/libstd/sys/windows/fs.rs#L260
        //   For now I'm just going to leave this test as-is.
        //
        let f = unsafe {
            File::from_raw_handle(CreateFileW(
                to_u16s(file_path).unwrap().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                // I read there's some security concerns if you don't use this
                SECURITY_SQOS_PRESENT,
                null_mut(),
            ))
        };

        let ecode =
            unsafe { super::super::ioctl::ioctl_with_ref(&f, FSCTL_SET_COMPRESSION, &compressed) };

        assert_eq!(ecode, 0);
        // set compressed short back to 0 for reading purposes,
        // otherwise we can't be sure we're the FSCTL_GET_COMPRESSION
        // is writing anything to the compressed pointer.
        compressed = 0;

        let ecode = unsafe {
            super::super::ioctl::ioctl_with_mut_ref(&f, FSCTL_GET_COMPRESSION, &mut compressed)
        };

        // now should be compressed
        assert_eq!(ecode, 0);
        assert_eq!(compressed, COMPRESSION_FORMAT_LZNT1);

        drop(f);
        // clean up
        dir.close().expect("Failed to close the temp directory.");
    }

    #[test]
    fn ioctl_with_val() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.dat");
        let file_path = file_path.as_path();

        // compressed = empty short for compressed status to be read into
        let mut compressed: c_ushort;

        // open our random file and write "foo" in it
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path)
            .unwrap();
        f.write_all(b"foo").expect("Failed to write bytes.");
        f.sync_all().expect("Failed to sync all.");

        // Now do a FSCTL_SET_COMPRESSED to set it to COMPRESSION_FORMAT_LZNT1.
        compressed = COMPRESSION_FORMAT_LZNT1;

        // NOTE: Theoretically I should be able to open this file like so:
        // let mut f = OpenOptions::new()
        //     .access_mode(GENERIC_WRITE|GENERIC_WRITE)
        //     .share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE)
        //     .open("test.dat").unwrap();
        //
        //   However, that does not work, and I'm not sure why.  Here's where
        //   the underlying std code is doing a CreateFileW:
        //   https://github.com/rust-lang/rust/blob/master/src/libstd/sys/windows/fs.rs#L260
        //   For now I'm just going to leave this test as-is.
        //
        let f = unsafe {
            File::from_raw_handle(CreateFileW(
                to_u16s(file_path).unwrap().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                // I read there's some security concerns if you don't use this
                SECURITY_SQOS_PRESENT,
                null_mut(),
            ))
        };

        // now we call ioctl_with_val, which isn't particularly any more helpful than
        // ioctl_with_ref except for the cases where the input is only a word long
        let ecode = unsafe {
            super::super::ioctl::ioctl_with_val(&f, FSCTL_SET_COMPRESSION, compressed.into())
        };

        assert_eq!(ecode, 0);
        // set compressed short back to 0 for reading purposes,
        // otherwise we can't be sure we're the FSCTL_GET_COMPRESSION
        // is writing anything to the compressed pointer.
        compressed = 0;

        let ecode = unsafe {
            super::super::ioctl::ioctl_with_mut_ref(&f, FSCTL_GET_COMPRESSION, &mut compressed)
        };

        // now should be compressed
        assert_eq!(ecode, 0);
        assert_eq!(compressed, COMPRESSION_FORMAT_LZNT1);

        drop(f);
        // clean up
        dir.close().expect("Failed to close the temp directory.");
    }
}
