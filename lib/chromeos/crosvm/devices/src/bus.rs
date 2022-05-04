// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles routing to devices in an address space.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::fmt;
use std::result;
use std::sync::Arc;

use remain::sorted;
use serde::{Deserialize, Serialize};
use sync::Mutex;
use thiserror::Error;

use crate::{PciAddress, PciDevice, VfioPlatformDevice};

/// Information about how a device was accessed.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct BusAccessInfo {
    /// Offset from base address that the device was accessed at.
    pub offset: u64,
    /// Absolute address of the device's access in its address space.
    pub address: u64,
    /// ID of the entity requesting a device access, usually the VCPU id.
    pub id: usize,
}

// Implement `Display` for `MinMax`.
impl std::fmt::Display for BusAccessInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Result of a write to a device's PCI configuration space.
/// This value represents the state change(s) that occurred due to the write.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConfigWriteResult {
    /// The BusRange in the vector will be removed from mmio_bus
    pub mmio_remove: Vec<BusRange>,

    /// The BusRange in the vector will be added into mmio_bus
    pub mmio_add: Vec<BusRange>,

    /// The BusRange in the vector will be removed from io_bus
    pub io_remove: Vec<BusRange>,

    /// The BusRange in the vector will be added into io_bus
    pub io_add: Vec<BusRange>,

    /// Device specified at PciAddress will be removed after this config write
    /// - 'Vec<PciAddress>>': specified device will be removed after this config write
    pub removed_pci_devices: Vec<PciAddress>,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum BusType {
    Mmio,
    Io,
}

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;

    /// Returns a unique id per device type suitable for metrics gathering.
    // TODO(225991065): Remove this default implementation when all of the crate is upstreamed.
    fn device_id(&self) -> u32 {
        0
    }
    /// Reads at `offset` from this device
    fn read(&mut self, offset: BusAccessInfo, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, offset: BusAccessInfo, data: &[u8]) {}
    /// Sets a register in the configuration space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset in to the register.
    fn config_register_write(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> ConfigWriteResult {
        ConfigWriteResult {
            ..Default::default()
        }
    }
    /// Gets a register from the configuration space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to read.
    fn config_register_read(&self, reg_idx: usize) -> u32 {
        0
    }
    /// Sets a register in the virtual config space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `value` - The value to be written.
    fn virtual_config_register_write(&mut self, reg_idx: usize, value: u32) {}
    /// Gets a register from the virtual config space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to read.
    fn virtual_config_register_read(&self, reg_idx: usize) -> u32 {
        0
    }
    /// Invoked when the device is sandboxed.
    fn on_sandboxed(&mut self) {}

    /// Gets a list of all ranges registered by this BusDevice.
    fn get_ranges(&self) -> Vec<(BusRange, BusType)> {
        Vec::new()
    }

    /// Invoked when the device is destroyed
    fn destroy_device(&mut self) {}
}

pub trait BusDeviceSync: BusDevice + Sync {
    fn read(&self, offset: BusAccessInfo, data: &mut [u8]);
    fn write(&self, offset: BusAccessInfo, data: &[u8]);
}

pub trait BusResumeDevice: Send {
    /// notify the devices which are invoked
    /// before the VM resumes form suspend.
    fn resume_imminent(&mut self) {}
}

/// The key to identify hotplug device from host view.
/// like host sysfs path for vfio pci device, host disk file
/// path for virtio block device
#[derive(Copy, Clone)]
pub enum HostHotPlugKey {
    Vfio { host_addr: PciAddress },
}

/// Trait for devices that notify hotplug event into guest
pub trait HotPlugBus {
    /// Notify hotplug in event into guest
    /// * 'addr' - the guest pci address for hotplug in device
    fn hot_plug(&mut self, addr: PciAddress);
    /// Notify hotplug out event into guest
    /// * 'addr' - the guest pci address for hotplug out device
    fn hot_unplug(&mut self, addr: PciAddress);
    /// Check whether the hotplug bus is available to add the new device
    ///
    /// - 'None': hotplug bus isn't match with host pci device
    /// - 'Some(bus_num)': hotplug bus is match and put the device at bus_num
    fn is_match(&self, host_addr: PciAddress) -> Option<u8>;
    /// Add hotplug device into this bus
    /// * 'host_key' - the key to identify hotplug device from host view
    /// * 'guest_addr' - the guest pci address for hotplug device
    fn add_hotplug_device(&mut self, host_key: HostHotPlugKey, guest_addr: PciAddress);
    /// get guest pci address from the specified host_key
    fn get_hotplug_device(&self, host_key: HostHotPlugKey) -> Option<PciAddress>;
}

/// Trait for generic device abstraction, that is, all devices that reside on BusDevice and want
/// to be converted back to its original type. Each new foo device must provide
/// as_foo_device() + as_foo_device_mut() + into_foo_device(), default impl methods return None.
pub trait BusDeviceObj {
    fn as_pci_device(&self) -> Option<&dyn PciDevice> {
        None
    }
    fn as_pci_device_mut(&mut self) -> Option<&mut dyn PciDevice> {
        None
    }
    fn into_pci_device(self: Box<Self>) -> Option<Box<dyn PciDevice>> {
        None
    }

    fn as_platform_device(&self) -> Option<&VfioPlatformDevice> {
        None
    }
    fn as_platform_device_mut(&mut self) -> Option<&mut VfioPlatformDevice> {
        None
    }
    fn into_platform_device(self: Box<Self>) -> Option<Box<VfioPlatformDevice>> {
        None
    }
}

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Bus Range not found")]
    Empty,
    /// The insertion failed because the new device overlapped with an old device.
    #[error("new device overlaps with an old device")]
    Overlap,
}

pub type Result<T> = result::Result<T, Error>;

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct BusRange {
    pub base: u64,
    pub len: u64,
}

impl BusRange {
    /// Returns true if `addr` is within the range.
    pub fn contains(&self, addr: u64) -> bool {
        self.base <= addr && addr < self.base + self.len
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        self.base < (base + len) && base < self.base + self.len
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        self.base.partial_cmp(&other.base)
    }
}

#[derive(Clone)]
enum BusDeviceEntry {
    OuterSync(Arc<Mutex<dyn BusDevice>>),
    InnerSync(Arc<dyn BusDeviceSync>),
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Clone)]
pub struct Bus {
    devices: Arc<Mutex<BTreeMap<BusRange, BusDeviceEntry>>>,
    access_id: usize,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: Arc::new(Mutex::new(BTreeMap::new())),
            access_id: 0,
        }
    }

    /// Sets the id that will be used for BusAccessInfo.
    pub fn set_access_id(&mut self, id: usize) {
        self.access_id = id;
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, BusDeviceEntry)> {
        let devices = self.devices.lock();
        let (range, dev) = devices
            .range(..=BusRange { base: addr, len: 1 })
            .rev()
            .next()?;
        Some((*range, dev.clone()))
    }

    fn get_device(&self, addr: u64) -> Option<(u64, u64, BusDeviceEntry)> {
        if let Some((range, dev)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                return Some((offset, addr, dev));
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(&self, device: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        let mut devices = self.devices.lock();
        if devices
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(Error::Overlap);
        }

        if devices
            .insert(BusRange { base, len }, BusDeviceEntry::OuterSync(device))
            .is_some()
        {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Puts the given device that implements BusDeviceSync at the given address space. Devices
    /// that implement BusDeviceSync manage thread safety internally, and thus can be written to
    /// by multiple threads simultaneously.
    pub fn insert_sync(&self, device: Arc<dyn BusDeviceSync>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        let mut devices = self.devices.lock();
        if devices
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(Error::Overlap);
        }

        if devices
            .insert(BusRange { base, len }, BusDeviceEntry::InnerSync(device))
            .is_some()
        {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Remove the given device at the given address space.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap);
        }

        let mut devices = self.devices.lock();
        if devices
            .iter()
            .any(|(range, _dev)| range.base == base && range.len == len)
        {
            let ret = devices.remove(&BusRange { base, len });
            if ret.is_some() {
                Ok(())
            } else {
                Err(Error::Empty)
            }
        } else {
            Err(Error::Empty)
        }
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((offset, address, dev)) = self.get_device(addr) {
            let io = BusAccessInfo {
                address,
                offset,
                id: self.access_id,
            };
            match dev {
                BusDeviceEntry::OuterSync(dev) => dev.lock().read(io, data),
                BusDeviceEntry::InnerSync(dev) => dev.read(io, data),
            }
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        if let Some((offset, address, dev)) = self.get_device(addr) {
            let io = BusAccessInfo {
                address,
                offset,
                id: self.access_id,
            };
            match dev {
                BusDeviceEntry::OuterSync(dev) => dev.lock().write(io, data),
                BusDeviceEntry::InnerSync(dev) => dev.write(io, data),
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {
        fn debug_label(&self) -> String {
            "dummy device".to_owned()
        }
    }

    struct ConstantDevice {
        uses_full_addr: bool,
    }

    impl BusDevice for ConstantDevice {
        fn debug_label(&self) -> String {
            "constant device".to_owned()
        }

        fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
            let addr = if self.uses_full_addr {
                info.address
            } else {
                info.offset
            };
            for (i, v) in data.iter_mut().enumerate() {
                *v = (addr as u8) + (i as u8);
            }
        }

        fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
            let addr = if self.uses_full_addr {
                info.address
            } else {
                info.offset
            };
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (addr as u8) + (i as u8))
            }
        }
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0f, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy, 0x0, 0x10).is_ok());
    }

    #[test]
    fn bus_insert_full_addr() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0f, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy, 0x0, 0x10).is_ok());
    }

    #[test]
    fn bus_read_write() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x16, &[0, 0, 0, 0]));
        assert!(!bus.read(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x20, &[0, 0, 0, 0]));
        assert!(!bus.read(0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x06, &[0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice {
            uses_full_addr: false,
        }));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn bus_read_write_full_addr_values() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice {
            uses_full_addr: true,
        }));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());

        let mut values = [0u8; 4];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0x10, 0x11, 0x12, 0x13]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [0x15, 0x16, 0x17, 0x18]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn bus_range_contains() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
        };
        assert!(a.contains(0x1000));
        assert!(a.contains(0x13ff));
        assert!(!a.contains(0xfff));
        assert!(!a.contains(0x1400));
        assert!(a.contains(0x1200));
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
        };
        assert!(a.overlaps(0x1000, 0x400));
        assert!(a.overlaps(0xf00, 0x400));
        assert!(a.overlaps(0x1000, 0x01));
        assert!(a.overlaps(0xfff, 0x02));
        assert!(a.overlaps(0x1100, 0x100));
        assert!(a.overlaps(0x13ff, 0x100));
        assert!(!a.overlaps(0x1400, 0x100));
        assert!(!a.overlaps(0xf00, 0x100));
    }
}
