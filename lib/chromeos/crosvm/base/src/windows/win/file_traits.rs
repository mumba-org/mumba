// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::super::{FileAllocate, WriteZeroesAt};
use std::{fs::File, io};

#[macro_export]
macro_rules! volatile_impl {
    ($ty:ty) => {
        // Unused imports are "unneeded" because the only usage of this macro already has those
        // names in scope.
        #[allow(unused_imports)]
        use crate::AsRawDescriptor as _;
        #[allow(unused_imports)]
        use std::convert::TryInto as _;
        #[allow(unused_imports)]
        use std::io::Seek as _;
        impl FileReadWriteVolatile for $ty {
            fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let mut bytes = 0;
                let ret = unsafe {
                    winapi::um::fileapi::ReadFile(
                        self.as_raw_descriptor(),
                        slice.as_ptr() as *mut libc::c_void,
                        slice.size().try_into().unwrap(),
                        &mut bytes,
                        std::ptr::null_mut(),
                    )
                };

                if ret > 0 {
                    Ok(bytes as usize)
                } else {
                    Err(Error::last_os_error())
                }
            }

            fn read_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
                if bufs.is_empty() {
                    return Ok(0);
                }

                // Windows has ReadFileScatter, but that requires the buffers to all be the same
                // size and aligned to a page size boundary.
                // readv makes some guarantees that we can't guarantee in windows, like atomicity.
                let mut ret = 0usize;
                for buf in bufs.iter() {
                    match self.read_volatile(*buf) {
                        Ok(bytes) => ret += bytes,
                        Err(_) => return Err(Error::last_os_error()),
                    }
                }

                Ok(ret)
            }

            fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let mut bytes = 0;
                let ret = unsafe {
                    winapi::um::fileapi::WriteFile(
                        self.as_raw_descriptor(),
                        slice.as_ptr() as *mut libc::c_void,
                        slice.size().try_into().unwrap(),
                        &mut bytes,
                        std::ptr::null_mut(),
                    )
                };

                if ret > 0 {
                    Ok(bytes as usize)
                } else {
                    Err(Error::last_os_error())
                }
            }

            fn write_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
                if bufs.is_empty() {
                    return Ok(0);
                }

                // Windows has WriteFileGather, but that requires the buffers to all be the same
                // size and aligned to a page size boundary, and only writes one page of data
                // from each buffer.
                // writev makes some guarantees that we can't guarantee in windows, like atomicity.
                let mut ret = 0usize;
                for buf in bufs.iter() {
                    match self.write_volatile(*buf) {
                        Ok(bytes) => ret += bytes,
                        Err(_) => return Err(Error::last_os_error()),
                    }
                }

                Ok(ret)
            }
        }
    };
}

#[macro_export]
macro_rules! volatile_at_impl {
    ($ty:ty) => {
        impl FileReadWriteAtVolatile for $ty {
            fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize> {
                // The unix implementation uses pread, which doesn't modify the file
                // pointer. Windows doesn't have an option for that, unfortunately.

                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let mut bytes = 0;

                let ret = unsafe {
                    let mut overlapped: winapi::um::minwinbase::OVERLAPPED = std::mem::zeroed();
                    overlapped.u.s_mut().Offset = offset as u32;
                    overlapped.u.s_mut().OffsetHigh = (offset >> 32) as u32;

                    winapi::um::fileapi::ReadFile(
                        self.as_raw_descriptor(),
                        slice.as_ptr() as *mut libc::c_void,
                        slice.size().try_into().unwrap(),
                        &mut bytes,
                        &mut overlapped,
                    )
                };

                if ret > 0 {
                    Ok(bytes as usize)
                } else {
                    Err(Error::last_os_error())
                }
            }

            fn read_vectored_at_volatile(
                &mut self,
                bufs: &[VolatileSlice],
                offset: u64,
            ) -> Result<usize> {
                if bufs.is_empty() {
                    return Ok(0);
                }

                // Windows has ReadFileScatter, but that requires the buffers to all be the same
                // size and aligned to a page size boundary.
                // preadv makes some guarantees that we can't guarantee in windows, like atomicity.
                let mut ret: usize = 0;
                for buf in bufs.iter() {
                    match self.read_at_volatile(*buf, offset + ret as u64) {
                        Ok(bytes) => ret += bytes,
                        Err(_) => return Err(Error::last_os_error()),
                    }
                }

                Ok(ret)
            }

            fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize> {
                // The unix implementation uses pwrite, which doesn't modify the file
                // pointer. Windows doesn't have an option for that, unfortunately.

                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let mut bytes = 0;

                let ret = unsafe {
                    let mut overlapped: winapi::um::minwinbase::OVERLAPPED = std::mem::zeroed();
                    overlapped.u.s_mut().Offset = offset as u32;
                    overlapped.u.s_mut().OffsetHigh = (offset >> 32) as u32;

                    winapi::um::fileapi::WriteFile(
                        self.as_raw_descriptor(),
                        slice.as_ptr() as *mut libc::c_void,
                        slice.size().try_into().unwrap(),
                        &mut bytes,
                        &mut overlapped,
                    )
                };

                if ret > 0 {
                    Ok(bytes as usize)
                } else {
                    Err(Error::last_os_error())
                }
            }

            fn write_vectored_at_volatile(
                &mut self,
                bufs: &[VolatileSlice],
                offset: u64,
            ) -> Result<usize> {
                if bufs.is_empty() {
                    return Ok(0);
                }

                // Windows has WriteFileGather, but that requires the buffers to all be the same
                // size and aligned to a page size boundary, and only writes one page of data
                // from each buffer.
                // pwritev makes some guarantees that we can't guarantee in windows, like atomicity.
                let mut ret: usize = 0;
                for buf in bufs.iter() {
                    match self.write_at_volatile(*buf, offset + ret as u64) {
                        Ok(bytes) => ret += bytes,
                        Err(_) => return Err(Error::last_os_error()),
                    }
                }

                Ok(ret as usize)
            }
        }
    };
}

impl FileAllocate for File {
    fn allocate(&mut self, offset: u64, len: u64) -> io::Result<()> {
        // The Windows equivalent of fallocate's default mode (allocate a zeroed block of space in a
        // file) is to just call write_zeros_at. There are not, at the time of writing, any syscalls
        // that will extend the file and zero the range while maintaining the disk allocation in a
        // more efficient manner.
        self.write_zeroes_all_at(offset, len as usize)
    }
}
