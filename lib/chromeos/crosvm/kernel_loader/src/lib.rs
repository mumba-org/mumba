// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::io::{Read, Seek, SeekFrom};
use std::mem;

use base::AsRawDescriptor;
use data_model::DataInit;
use remain::sorted;
use thiserror::Error;
use vm_memory::{GuestAddress, GuestMemory};

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(clippy::all)]
mod elf;

// Elf64_Ehdr is plain old data with no implicit padding.
unsafe impl data_model::DataInit for elf::Elf64_Ehdr {}

// Elf64_Phdr is plain old data with no implicit padding.
unsafe impl data_model::DataInit for elf::Elf64_Phdr {}

#[sorted]
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("trying to load big-endian binary on little-endian machine")]
    BigEndianElfOnLittle,
    #[error("failed writing command line to guest memory")]
    CommandLineCopy,
    #[error("command line overflowed guest memory")]
    CommandLineOverflow,
    #[error("invalid Elf magic number")]
    InvalidElfMagicNumber,
    #[error("invalid Program Header Address")]
    InvalidProgramHeaderAddress,
    #[error("invalid Program Header memory size")]
    InvalidProgramHeaderMemSize,
    #[error("invalid program header offset")]
    InvalidProgramHeaderOffset,
    #[error("invalid program header size")]
    InvalidProgramHeaderSize,
    #[error("unable to read elf header")]
    ReadElfHeader,
    #[error("unable to read kernel image")]
    ReadKernelImage,
    #[error("unable to read program header")]
    ReadProgramHeader,
    #[error("unable to seek to elf start")]
    SeekElfStart,
    #[error("unable to seek to kernel start")]
    SeekKernelStart,
    #[error("unable to seek to program header")]
    SeekProgramHeader,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Loads a kernel from a vmlinux elf image to a slice
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_start` - The offset into `guest_mem` at which to load the kernel.
/// * `kernel_image` - Input vmlinux image.
pub fn load_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    mut kernel_image: &mut F,
) -> Result<u64>
where
    F: Read + Seek + AsRawDescriptor,
{
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekElfStart)?;
    let ehdr = elf::Elf64_Ehdr::from_reader(&mut kernel_image).map_err(|_| Error::ReadElfHeader)?;

    // Sanity checks
    if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
    {
        return Err(Error::InvalidElfMagicNumber);
    }
    if ehdr.e_ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
        return Err(Error::BigEndianElfOnLittle);
    }
    if ehdr.e_phentsize as usize != mem::size_of::<elf::Elf64_Phdr>() {
        return Err(Error::InvalidProgramHeaderSize);
    }
    if (ehdr.e_phoff as usize) < mem::size_of::<elf::Elf64_Ehdr>() {
        // If the program header is backwards, bail.
        return Err(Error::InvalidProgramHeaderOffset);
    }

    kernel_image
        .seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdrs = (0..ehdr.e_phnum)
        .enumerate()
        .map(|_| {
            elf::Elf64_Phdr::from_reader(&mut kernel_image).map_err(|_| Error::ReadProgramHeader)
        })
        .collect::<Result<Vec<elf::Elf64_Phdr>>>()?;

    let mut kernel_end = 0;

    // Read in each section pointed to by the program headers.
    for phdr in &phdrs {
        if phdr.p_type != elf::PT_LOAD || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = kernel_start
            .checked_add(phdr.p_paddr)
            .ok_or(Error::InvalidProgramHeaderAddress)?;
        guest_mem
            .read_to_memory(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;

        kernel_end = mem_offset
            .offset()
            .checked_add(phdr.p_memsz)
            .ok_or(Error::InvalidProgramHeaderMemSize)?;
    }

    Ok(kernel_end)
}

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line.
pub fn load_cmdline(
    guest_mem: &GuestMemory,
    guest_addr: GuestAddress,
    cmdline: &CStr,
) -> Result<()> {
    let len = cmdline.to_bytes().len();
    if len == 0 {
        return Ok(());
    }

    let end = guest_addr
        .checked_add(len as u64 + 1)
        .ok_or(Error::CommandLineOverflow)?; // Extra for null termination.
    if end > guest_mem.end_addr() {
        return Err(Error::CommandLineOverflow);
    }

    guest_mem
        .write_at_addr(cmdline.to_bytes_with_nul(), guest_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempfile;
    use vm_memory::{GuestAddress, GuestMemory};

    const MEM_SIZE: u64 = 0x8000;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap()
    }

    #[test]
    fn cmdline_overflow() {
        let gm = create_guest_mem();
        let cmdline_address = GuestAddress(MEM_SIZE - 5);
        assert_eq!(
            Err(Error::CommandLineOverflow),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"12345\0").unwrap()
            )
        );
    }

    #[test]
    fn cmdline_write_end() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        assert_eq!(
            Ok(()),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"1234\0").unwrap()
            )
        );
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }

    // Elf64 image that prints hello world on x86_64.
    fn make_elf_bin() -> File {
        let elf_bytes = include_bytes!("test_elf.bin");
        let mut file = tempfile().expect("failed to create tempfile");
        file.write_all(elf_bytes)
            .expect("failed to write elf to shared memoy");
        file
    }

    fn mutate_elf_bin(mut f: &File, offset: u64, val: u8) {
        f.seek(SeekFrom::Start(offset))
            .expect("failed to seek file");
        f.write_all(&[val])
            .expect("failed to write mutated value to file");
    }

    #[test]
    fn load_elf() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut image = make_elf_bin();
        assert_eq!(Ok(16613), load_kernel(&gm, kernel_addr, &mut image));
    }

    #[test]
    fn bad_magic() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        mutate_elf_bin(&bad_image, 0x1, 0x33);
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&gm, kernel_addr, &mut bad_image)
        );
    }

    #[test]
    fn bad_endian() {
        // Only little endian is supported
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        mutate_elf_bin(&bad_image, 0x5, 2);
        assert_eq!(
            Err(Error::BigEndianElfOnLittle),
            load_kernel(&gm, kernel_addr, &mut bad_image)
        );
    }

    #[test]
    fn bad_phoff() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        mutate_elf_bin(&bad_image, 0x20, 0x10);
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_kernel(&gm, kernel_addr, &mut bad_image)
        );
    }
}
