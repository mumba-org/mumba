// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::{read, write, File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, bail, Context, Result};
use base::{error, Tube};
use data_model::DataInit;
use sync::Mutex;
use vm_control::{VmRequest, VmResponse};

use crate::pci::{PciCapabilityID, PciClassCode};

use crate::pci::pci_configuration::{
    PciBridgeSubclass, CAPABILITY_LIST_HEAD_OFFSET, PCI_CAP_NEXT_POINTER,
};

use crate::pci::pcie::pci_bridge::{
    PciBridgeBusRange, BR_BUS_NUMBER_REG, BR_MEM_BASE_MASK, BR_MEM_BASE_SHIFT, BR_MEM_LIMIT_MASK,
    BR_MEM_MINIMUM, BR_MEM_REG, BR_PREF_MEM_64BIT, BR_PREF_MEM_BASE_HIGH_REG,
    BR_PREF_MEM_LIMIT_HIGH_REG, BR_PREF_MEM_LOW_REG, BR_WINDOW_ALIGNMENT,
};

use crate::pci::pcie::*;

// Host Pci device's sysfs config file
struct PciHostConfig {
    config_file: File,
}

impl PciHostConfig {
    // Create a new host pci device's sysfs config file
    fn new(host_sysfs_path: &Path) -> Result<Self> {
        let mut config_path = PathBuf::new();
        config_path.push(host_sysfs_path);
        config_path.push("config");
        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(config_path.as_path())
            .with_context(|| format!("failed to open: {}", config_path.display()))?;
        Ok(PciHostConfig { config_file: f })
    }

    // Read host pci device's config register
    fn read_config<T: DataInit>(&self, offset: u64) -> T {
        let length = std::mem::size_of::<T>();
        let mut buf = vec![0u8; length];
        if offset % length as u64 != 0 {
            error!(
                "read_config, offset {} isn't aligned to length {}",
                offset, length
            );
        } else if let Err(e) = self.config_file.read_exact_at(&mut buf, offset) {
            error!("failed to read host sysfs config: {}", e);
        }

        T::from_slice(&buf)
            .copied()
            .expect("failed to convert host sysfs config data from slice")
    }

    // write host pci device's config register
    #[allow(dead_code)]
    fn write_config(&self, offset: u64, data: &[u8]) {
        if offset % data.len() as u64 != 0 {
            error!(
                "write_config, offset {} isn't aligned to length {}",
                offset,
                data.len()
            );
            return;
        }
        if let Err(e) = self.config_file.write_all_at(data, offset) {
            error!("failed to write host sysfs config: {}", e);
        }
    }
}

// Find the added pcie endpoint device
fn visit_children(dir: &Path) -> Result<PathBuf> {
    // Each pci device has a sysfs directory
    if !dir.is_dir() {
        bail!("{} isn't directory", dir.display());
    }

    let class_path = dir.join("class");
    let class_id = read(class_path.as_path())
        .with_context(|| format!("failed to read {}", class_path.display()))?;
    // If the device isn't pci bridge, it is the target pcie endpoint device
    if !class_id.starts_with("0x0604".as_bytes()) {
        return Ok(dir.to_path_buf());
    }

    // Loop device sysfs subdirectory
    let entries = dir
        .read_dir()
        .with_context(|| format!("failed to read dir {}", dir.display()))?;
    for entry in entries {
        let sub_dir = match entry {
            Ok(sub) => sub,
            _ => continue,
        };

        if !sub_dir.path().is_dir() {
            continue;
        }

        let name = sub_dir
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("failed to get dir name"))?;
        // Child pci device has name format 0000:xx:xx.x, length is 12
        if name.len() != 12 || !name.starts_with("0000:") {
            continue;
        }
        let child_path = dir.join(name);
        match visit_children(child_path.as_path()) {
            Ok(child) => return Ok(child),
            Err(_) => continue,
        }
    }
    Err(anyhow!(
        "pcie child endpoint device isn't exist in {}",
        dir.display()
    ))
}

struct HotplugWorker {
    host_name: String,
}

impl HotplugWorker {
    fn run(&self, vm_socket: Arc<Mutex<Tube>>, child_exist: Arc<Mutex<bool>>) -> Result<()> {
        let mut host_sysfs = PathBuf::new();
        host_sysfs.push("/sys/bus/pci/devices/");
        host_sysfs.push(self.host_name.clone());
        let rescan_path = host_sysfs.join("rescan");
        // Let pcie root port rescan to find the added or removed children devices
        write(rescan_path.as_path(), "1")
            .with_context(|| format!("failed to write {}", rescan_path.display()))?;

        // If child device existed, but code run here again, this means host has a
        // hotplug out event, after the above rescan, host should find the removed
        // child device, and host vfio-pci kernel driver should notify crosvm vfio-pci
        // devie such hotplug out event, so nothing is needed to do here, just return
        // it now.
        let mut child_exist = child_exist.lock();
        if *child_exist {
            return Ok(());
        }

        // Probe the new added pcied endpoint device
        let child = visit_children(host_sysfs.as_path())?;

        // In order to bind device to vfio-pci driver, get device VID and DID
        let vendor_path = child.join("vendor");
        let vendor_id = read(vendor_path.as_path())
            .with_context(|| format!("failed to read {}", vendor_path.display()))?;
        // Remove the first two elements 0x
        let prefix: &str = "0x";
        let vendor = match vendor_id.strip_prefix(prefix.as_bytes()) {
            Some(v) => v.to_vec(),
            None => vendor_id,
        };
        let device_path = child.join("device");
        let device_id = read(device_path.as_path())
            .with_context(|| format!("failed to read {}", device_path.display()))?;
        // Remove the first two elements 0x
        let device = match device_id.strip_prefix(prefix.as_bytes()) {
            Some(d) => d.to_vec(),
            None => device_id,
        };
        let new_id = vec![
            String::from_utf8_lossy(&vendor),
            String::from_utf8_lossy(&device),
        ]
        .join(" ");
        write("/sys/bus/pci/drivers/vfio-pci/new_id", &new_id)
            .with_context(|| format!("failed to write {} into vfio-pci/new_id", new_id))?;

        // Request to hotplug the new added pcie device into guest
        let request = VmRequest::VfioCommand {
            vfio_path: child.clone(),
            add: true,
        };
        vm_socket
            .lock()
            .send(&request)
            .with_context(|| format!("failed to send hotplug request for {}", child.display()))?;
        vm_socket.lock().recv::<VmResponse>().with_context(|| {
            format!("failed to receive hotplug response for {}", child.display())
        })?;

        *child_exist = true;

        Ok(())
    }
}

const PCI_CONFIG_DEVICE_ID: u64 = 0x02;
const PCI_BASE_CLASS_CODE: u64 = 0x0B;
const PCI_SUB_CLASS_CODE: u64 = 0x0A;

/// Pcie root port device has a corresponding host pcie root port.
pub struct PcieHostRootPort {
    host_config: PciHostConfig,
    host_name: String,
    hotplug_in_process: Arc<Mutex<bool>>,
    hotplug_child_exist: Arc<Mutex<bool>>,
    vm_socket: Arc<Mutex<Tube>>,
}

impl PcieHostRootPort {
    /// Create PcieHostRootPort, host_syfsfs_patch specify host pcie root port
    /// sysfs path.
    pub fn new(host_sysfs_path: &Path, socket: Tube) -> Result<Self> {
        let host_config = PciHostConfig::new(host_sysfs_path)?;
        let host_name = host_sysfs_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let base_class: u8 = host_config.read_config(PCI_BASE_CLASS_CODE);
        if base_class != PciClassCode::BridgeDevice.get_register_value() {
            return Err(anyhow!("host {} isn't bridge", host_name));
        }
        let sub_class: u8 = host_config.read_config(PCI_SUB_CLASS_CODE);
        if sub_class != PciBridgeSubclass::PciToPciBridge as u8 {
            return Err(anyhow!("host {} isn't pci to pci bridge", host_name));
        }

        let mut pcie_cap_reg: u8 = 0;

        let mut cap_next: u8 = host_config.read_config(CAPABILITY_LIST_HEAD_OFFSET as u64);
        let mut counter: u16 = 0;
        while cap_next != 0 && counter < 256 {
            let cap_id: u8 = host_config.read_config(cap_next.into());
            if cap_id == PciCapabilityID::PciExpress as u8 {
                pcie_cap_reg = cap_next;
                break;
            }
            let offset = cap_next as u64 + PCI_CAP_NEXT_POINTER as u64;
            cap_next = host_config.read_config(offset);
            counter += 1;
        }

        if pcie_cap_reg == 0 {
            return Err(anyhow!("host {} isn't pcie device", host_name));
        }

        let device_cap: u8 = host_config.read_config(pcie_cap_reg as u64 + PCIE_CAP_VERSION as u64);
        if (device_cap >> PCIE_TYPE_SHIFT) != PcieDevicePortType::RootPort as u8 {
            return Err(anyhow!("host {} isn't pcie root port", host_name));
        }

        Ok(PcieHostRootPort {
            host_config,
            host_name,
            hotplug_in_process: Arc::new(Mutex::new(false)),
            hotplug_child_exist: Arc::new(Mutex::new(false)),
            vm_socket: Arc::new(Mutex::new(socket)),
        })
    }

    pub fn get_bus_range(&self) -> PciBridgeBusRange {
        let bus_num: u32 = self.host_config.read_config((BR_BUS_NUMBER_REG * 4) as u64);
        let primary = (bus_num & 0xFF) as u8;
        let secondary = ((bus_num >> 8) & 0xFF) as u8;
        let subordinate = ((bus_num >> 16) & 0xFF) as u8;

        PciBridgeBusRange {
            primary,
            secondary,
            subordinate,
        }
    }

    pub fn read_device_id(&self) -> u16 {
        self.host_config.read_config::<u16>(PCI_CONFIG_DEVICE_ID)
    }

    pub fn host_name(&self) -> String {
        self.host_name.clone()
    }

    pub fn read_config(&self, reg_idx: usize, data: &mut u32) {
        if reg_idx == 3 {
            // device header type
            *data = self.host_config.read_config(0x0C);
        }
    }

    pub fn write_config(&mut self, _reg_idx: usize, _offset: u64, _data: &[u8]) {}

    pub fn get_bridge_window_size(&self) -> (u64, u64) {
        let br_memory: u32 = self.host_config.read_config(BR_MEM_REG as u64 * 4);
        let mem_base = (br_memory & BR_MEM_BASE_MASK) << BR_MEM_BASE_SHIFT;
        let mem_limit = br_memory & BR_MEM_LIMIT_MASK;
        let mem_size = if mem_limit > mem_base {
            (mem_limit - mem_base) as u64 + BR_WINDOW_ALIGNMENT
        } else {
            BR_MEM_MINIMUM
        };
        let br_pref_mem_low: u32 = self.host_config.read_config(BR_PREF_MEM_LOW_REG as u64 * 4);
        let pref_mem_base_low = (br_pref_mem_low & BR_MEM_BASE_MASK) << BR_MEM_BASE_SHIFT;
        let pref_mem_limit_low = br_pref_mem_low & BR_MEM_LIMIT_MASK;
        let mut pref_mem_base: u64 = pref_mem_base_low as u64;
        let mut pref_mem_limit: u64 = pref_mem_limit_low as u64;
        if br_pref_mem_low & BR_PREF_MEM_64BIT == BR_PREF_MEM_64BIT {
            // 64bit prefetch memory
            let pref_mem_base_high: u32 = self
                .host_config
                .read_config(BR_PREF_MEM_BASE_HIGH_REG as u64 * 4);
            let pref_mem_limit_high: u32 = self
                .host_config
                .read_config(BR_PREF_MEM_LIMIT_HIGH_REG as u64 * 4);
            pref_mem_base = ((pref_mem_base_high as u64) << 32) | (pref_mem_base_low as u64);
            pref_mem_limit = ((pref_mem_limit_high as u64) << 32) | (pref_mem_limit_low as u64);
        }
        let pref_mem_size = if pref_mem_limit > pref_mem_base {
            pref_mem_limit - pref_mem_base + BR_WINDOW_ALIGNMENT
        } else {
            BR_MEM_MINIMUM
        };

        (mem_size, pref_mem_size)
    }

    pub fn hotplug_probe(&mut self) {
        if *self.hotplug_in_process.lock() {
            return;
        }

        let hotplug_process = self.hotplug_in_process.clone();
        let child_exist = self.hotplug_child_exist.clone();
        let socket = self.vm_socket.clone();
        let name = self.host_name.clone();
        let _ = thread::Builder::new()
            .name("pcie_hotplug".to_string())
            .spawn(move || {
                let mut hotplug = hotplug_process.lock();
                *hotplug = true;
                let hotplug_worker = HotplugWorker { host_name: name };
                let _ = hotplug_worker.run(socket, child_exist);
                *hotplug = false;
            });
    }

    pub fn hot_unplug(&mut self) {
        *self.hotplug_child_exist.lock() = false;
    }
}
