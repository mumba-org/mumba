// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::mem::size_of;

use base::{FileReadWriteAtVolatile, WriteZeroes};
use data_model::VolatileSlice;

/// A qcow file. Allows reading/writing clusters and appending clusters.
#[derive(Debug)]
pub struct QcowRawFile {
    file: File,
    cluster_size: u64,
    cluster_mask: u64,
}

impl QcowRawFile {
    /// Creates a `QcowRawFile` from the given `File`, `None` is returned if `cluster_size` is not
    /// a power of two.
    pub fn from(file: File, cluster_size: u64) -> Option<Self> {
        if cluster_size.count_ones() != 1 {
            return None;
        }
        Some(QcowRawFile {
            file,
            cluster_size,
            cluster_mask: cluster_size - 1,
        })
    }

    /// Reads `count` 64 bit offsets and returns them as a vector.
    /// `mask` optionally ands out some of the bits on the file.
    pub fn read_pointer_table(
        &mut self,
        offset: u64,
        count: u64,
        mask: Option<u64>,
    ) -> io::Result<Vec<u64>> {
        let mut table = vec![0; count as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        let mask = mask.unwrap_or(u64::max_value());
        for ptr in &mut table {
            let mut value = [0u8; 8];
            self.file.read_exact(&mut value)?;
            *ptr = u64::from_be_bytes(value) & mask;
        }
        Ok(table)
    }

    /// Reads a cluster's worth of 64 bit offsets and returns them as a vector.
    /// `mask` optionally ands out some of the bits on the file.
    pub fn read_pointer_cluster(&mut self, offset: u64, mask: Option<u64>) -> io::Result<Vec<u64>> {
        let count = self.cluster_size / size_of::<u64>() as u64;
        self.read_pointer_table(offset, count, mask)
    }

    /// Writes `table` of u64 pointers to `offset` in the file.
    /// `non_zero_flags` will be ORed with all non-zero values in `table`.
    /// writing.
    pub fn write_pointer_table(
        &mut self,
        offset: u64,
        table: &[u64],
        non_zero_flags: u64,
    ) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buffer = BufWriter::with_capacity(table.len() * size_of::<u64>(), &self.file);
        for addr in table {
            let val = if *addr == 0 {
                0
            } else {
                *addr | non_zero_flags
            };
            buffer.write_all(&val.to_be_bytes())?;
        }
        Ok(())
    }

    /// Read a refcount block from the file and returns a Vec containing the block.
    /// Always returns a cluster's worth of data.
    pub fn read_refcount_block(&mut self, offset: u64) -> io::Result<Vec<u16>> {
        let count = self.cluster_size / size_of::<u16>() as u64;
        let mut table = vec![0; count as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        for refcount in &mut table {
            let mut value = [0u8; 2];
            self.file.read_exact(&mut value)?;
            *refcount = u16::from_be_bytes(value);
        }
        Ok(table)
    }

    /// Writes a refcount block to the file.
    pub fn write_refcount_block(&mut self, offset: u64, table: &[u16]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buffer = BufWriter::with_capacity(table.len() * size_of::<u16>(), &self.file);
        for count in table {
            buffer.write_all(&count.to_be_bytes())?;
        }
        Ok(())
    }

    /// Allocates a new cluster at the end of the current file, return the address.
    pub fn add_cluster_end(&mut self, max_valid_cluster_offset: u64) -> io::Result<Option<u64>> {
        // Determine where the new end of the file should be and set_len, which
        // translates to truncate(2).
        let file_end: u64 = self.file.seek(SeekFrom::End(0))?;
        let new_cluster_address: u64 = (file_end + self.cluster_size - 1) & !self.cluster_mask;

        if new_cluster_address > max_valid_cluster_offset {
            return Ok(None);
        }

        self.file.set_len(new_cluster_address + self.cluster_size)?;

        Ok(Some(new_cluster_address))
    }

    /// Returns a reference to the underlying file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Returns a mutable reference to the underlying file.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Returns the size of the file's clusters.
    pub fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Returns the offset of `address` within a cluster.
    pub fn cluster_offset(&self, address: u64) -> u64 {
        address & self.cluster_mask
    }

    /// Zeros out a cluster in the file.
    pub fn zero_cluster(&mut self, address: u64) -> io::Result<()> {
        let cluster_size = self.cluster_size as usize;
        self.file.seek(SeekFrom::Start(address))?;
        self.file.write_zeroes_all(cluster_size)?;
        Ok(())
    }

    /// Writes
    pub fn write_cluster(&mut self, address: u64, mut initial_data: Vec<u8>) -> io::Result<()> {
        if (initial_data.len() as u64) < self.cluster_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`initial_data` is too small",
            ));
        }
        let volatile_slice = VolatileSlice::new(&mut initial_data[..self.cluster_size as usize]);
        self.file.write_all_at_volatile(volatile_slice, address)
    }
}
