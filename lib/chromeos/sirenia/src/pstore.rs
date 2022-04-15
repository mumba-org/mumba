// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Creates the emulated pstore and copies it back to RAMOOPS memory on reboot.

use std::cmp;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use data_model::{volatile_memory::VolatileMemory, DataInit};
use sys_util::{error, info, MappedRegion, MemoryMapping};

const RAMOOPS_UNBIND: &str = "/sys/devices/platform/ramoops.0/driver/unbind";
const RAMOOPS_BUS_ID: &[u8] = b"ramoops.0";

const RAMOOPS_REGION_HEADER_SIZE: usize = 12;
const RAMOOPS_DEFAULT_REGION_SIZE: usize = 0x20000;
const PSTORE_CONSOLE_FILENAME: &str = "console-ramoops-0";
const PSTORE_PMSG_FILENAME: &str = "pmsg-ramoops-0";

/// Copy contents of emulated pstore to RAMOOPS memory.
pub fn save_pstore(pstore_path: &str) -> Result<()> {
    // Unbind the hypervisor ramoops driver so that it doesn't clobber our
    // writes. If this fails, we continue anyway since the dmesg buffer will
    // still be preserved as long as the hypervisor does not crash.
    if let Err(e) = unbind_ramoops() {
        error!("Error (ignored): {:?}", e);
    }

    let pstore_fd = File::open(pstore_path)
        .with_context(|| format!("Failed to open pstore file: {}", pstore_path))?;
    let ramoops = mmap_ramoops()?;
    ramoops
        .read_to_memory(0, &pstore_fd, ramoops.size())
        .context("Failed to copy emulated pstore to ramoops memory")
}

fn unbind_ramoops() -> Result<()> {
    fs::write(RAMOOPS_UNBIND, RAMOOPS_BUS_ID).context("Failed to unbind ramoops driver")
}

fn get_goog9999_range(line: &str) -> Result<Option<(u64, usize)>> {
    // We are looking for a line in the following format (with leading spaces):
    //   769fa000-76af9fff : GOOG9999:00
    if let Some((range, name)) = line.split_once(':') {
        if name.trim() == "GOOG9999:00" {
            if let Some((begin, end)) = range.trim().split_once('-') {
                let begin_addr = u64::from_str_radix(begin, 16)
                    .map_err(|_| anyhow!("Invalid begin address: {}", line))?;
                let end_addr = u64::from_str_radix(end, 16)
                    .map_err(|_| anyhow!("Invalid end address: {}", line))?;
                let len = (end_addr
                    .checked_sub(begin_addr)
                    .ok_or_else(|| anyhow!("Invalid range: {}", line))?
                    + 1) as usize;
                return Ok(Some((begin_addr, len)));
            }
        }
    }
    Ok(None)
}

fn get_ramoops_location() -> Result<(u64, usize)> {
    // When the ramoops driver is enabled, and is using the GOOG9999 region,
    // this info is in /sys/module/ramoops/parameters/mem_{address|size}.
    // However, if the ramoops driver is disabled, or if it has been overridden
    // with kernel command line parameters (say, because we are in a VM), this
    // approach fails. Therefore, we parse /proc/iomem for this info.
    let iomem = File::open("/proc/iomem").context("Failed to open /proc/iomem")?;
    for line in BufReader::new(iomem).lines() {
        let l = line.context("Error reading from /proc/iomem")?;
        if let Some((addr, len)) = get_goog9999_range(&l)? {
            info!("pstore: using ramoops {:#x}@{:#x}", len, addr);
            return Ok((addr, len));
        }
    }
    bail!("Unable to find mapping for GOOG9999 in /proc/iomem");
}

fn mmap_ramoops() -> Result<MemoryMapping> {
    let (ramoops_addr, ramoops_len) = get_ramoops_location()?;
    let devmem = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_SYNC)
        .open("/dev/mem")
        .context("Failed to open /dev/mem")?;
    MemoryMapping::from_fd_offset(&devmem, ramoops_len, ramoops_addr)
        .context("Failed to mmap /dev/mem")
}

fn get_ramoops_region_size(name: &str) -> usize {
    // Chrome OS sets all regions except dmesg to the same size, so we
    // use that as the default size here in case of failures.
    let path = format!("/sys/module/ramoops/parameters/{}_size", name);
    match fs::read_to_string(&path) {
        Err(e) => {
            error!("Error reading {}: {}", path, e);
            RAMOOPS_DEFAULT_REGION_SIZE
        }
        Ok(v) => usize::from_str(v.trim())
            .with_context(|| format!("Could not parse {}: {:?}", path, v))
            .unwrap_or_else(|e| {
                error!("Error: {}", e);
                RAMOOPS_DEFAULT_REGION_SIZE
            }),
    }
}

// See fs/pstore/ram_core.c in the kernel for the header definition.
#[derive(Copy, Clone)]
#[repr(C)]
struct RamoopsRegionHeader {
    sig: [u8; 4], // signature, eg. b"DBGC"
    start: u32,   // offset to write next
    size: u32,    // bytes stored
}

// Safe because PstoreRegionHeader is plain data.
unsafe impl DataInit for RamoopsRegionHeader {}

/// Copy data from the specified /sys/fs/pstore file to the emulated pstore.
fn restore_pstore_region(
    emulated_pstore: &MemoryMapping,
    offset: usize,
    region_size: usize,
    fname: &str,
) -> Result<()> {
    // If there is no data in this ramoops region, the file will not exist.
    let path: PathBuf = ["/sys/fs/pstore", fname].iter().collect();
    if !path.is_file() {
        return Ok(());
    }

    // Write header
    let flen = path.metadata()?.len() as usize;
    let data_size: u32 = cmp::min(flen, region_size - RAMOOPS_REGION_HEADER_SIZE) as u32;
    let header = RamoopsRegionHeader {
        sig: *b"DBGC",
        start: data_size,
        size: data_size,
    };
    emulated_pstore.write_obj(header, offset)?;

    // Write data
    let dataf =
        File::open(&path).with_context(|| format!("Failed to open: {}", path.to_string_lossy()))?;
    emulated_pstore
        .read_to_memory(
            offset + RAMOOPS_REGION_HEADER_SIZE,
            &dataf,
            data_size as usize,
        )
        .with_context(|| format!("Failed to write {} to pstore file", fname))?;
    info!(
        "pstore: wrote {} bytes to region at {:#x} from {}",
        data_size,
        offset,
        path.to_string_lossy()
    );
    Ok(())
}

/// Set up emulated pstore by copying from RAMOOPS memory and /sys/fs/pstore.
pub fn restore_pstore(pstore_path: &str) -> Result<()> {
    // We never read from this file, but mmap requires read permissions.
    let outputf = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(pstore_path)
        .with_context(|| format!("Failed to open pstore file: {}", pstore_path))?;

    // Use identical size and settings for physical and emulated ramoops.
    let ramoops = mmap_ramoops()?;
    outputf
        .set_len(ramoops.size() as u64)
        .context("Failed to resize pstore file")?;
    outputf
        .sync_all()
        .context("Failed to sync pstore file after resize")?;
    let emulated_pstore =
        MemoryMapping::from_fd(&outputf, ramoops.size()).context("Failed to mmap pstore file")?;

    let console_size = get_ramoops_region_size("console");
    let ftrace_size = get_ramoops_region_size("ftrace");
    let pmsg_size = get_ramoops_region_size("pmsg");
    let dmesg_size = ramoops.size() - console_size - ftrace_size - pmsg_size;
    let console_offset = dmesg_size;
    let ftrace_offset = console_offset + console_size;
    let pmsg_offset = ftrace_offset + ftrace_size;
    info!(
        "pstore offsets: console={:#x} ftrace={:#x} pmsg={:#x}",
        console_offset, ftrace_offset, pmsg_offset
    );

    // Copy the dmesg regions as-is from hardware ramoops to pstore file since
    // they are not being written to. For the rest of the regions, copy from
    // files in /sys/fs/pstore.
    ramoops
        .get_slice(0, dmesg_size)?
        .copy_to_volatile_slice(emulated_pstore.get_slice(0, dmesg_size)?);

    // For everything except dmesg, use the files in /sys/fs/pstore.
    // TODO(b/221453622): Handle ftrace buffers.
    restore_pstore_region(
        &emulated_pstore,
        console_offset,
        console_size,
        PSTORE_CONSOLE_FILENAME,
    )?;
    restore_pstore_region(
        &emulated_pstore,
        pmsg_offset,
        pmsg_size,
        PSTORE_PMSG_FILENAME,
    )?;
    emulated_pstore
        .msync()
        .context("Unable to sync pstore file")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_iomem() {
        assert_eq!(
            get_goog9999_range("  769fa000-76af9fff : GOOG9999:00\n").unwrap(),
            Some((0x769fa000, 1048576))
        );
        assert_eq!(
            get_goog9999_range("769fa000-76af9fff:GOOG9999:00").unwrap(),
            Some((0x769fa000, 1048576))
        );
        assert_eq!(
            get_goog9999_range("    769fa000-76af9fff  :   GOOG9999:00").unwrap(),
            Some((0x769fa000, 1048576))
        );
        assert_eq!(
            get_goog9999_range("  769fa000-76af9fff : GOOG9999:00\n").unwrap(),
            Some((0x769fa000, 1048576))
        );
        assert_eq!(
            get_goog9999_range("fe010000-fe010fff : vfio-pci\n").unwrap(),
            None
        );
        assert_eq!(get_goog9999_range("GOOG9999:00\n").unwrap(), None);
        assert_eq!(get_goog9999_range(": GOOG9999:00\n").unwrap(), None);
        assert_eq!(
            get_goog9999_range("769fa000 : GOOG9999:00\n").unwrap(),
            None
        );
        assert!(get_goog9999_range("769fa000-76af9fffX : GOOG9999:00\n").is_err());
        assert!(get_goog9999_range("769fa000X-76af9fff : GOOG9999:00\n").is_err());
        assert!(get_goog9999_range("76af9fff-769fa000 : GOOG9999:00\n").is_err());
    }

    #[test]
    fn check_ramoops_region_header_size() {
        assert_eq!(
            std::mem::size_of::<RamoopsRegionHeader>(),
            RAMOOPS_REGION_HEADER_SIZE
        )
    }
}
