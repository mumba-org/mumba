// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use crate::vfio::{VfioDevice, VfioError, VfioIrq};
use crate::{BusAccessInfo, BusDevice, BusDeviceObj, IrqEdgeEvent, IrqLevelEvent};
use anyhow::{bail, Context, Result};
use base::{
    error, pagesize, AsRawDescriptor, AsRawDescriptors, Event, MappedRegion, MemoryMapping,
    MemoryMappingBuilder, RawDescriptor, Tube,
};
use resources::SystemAllocator;
use std::fs::File;
use std::sync::Arc;
use std::u32;
use vfio_sys::*;
use vm_control::{VmMemoryDestination, VmMemoryRequest, VmMemoryResponse, VmMemorySource};

struct MmioInfo {
    index: u32,
    start: u64,
    length: u64,
}

pub struct VfioPlatformDevice {
    device: Arc<VfioDevice>,
    interrupt_edge_evt: Vec<IrqEdgeEvent>,
    interrupt_level_evt: Vec<IrqLevelEvent>,
    mmio_regions: Vec<MmioInfo>,
    vm_socket_mem: Tube,
    // scratch MemoryMapping to avoid unmap beform vm exit
    mem: Vec<MemoryMapping>,
}

impl BusDevice for VfioPlatformDevice {
    fn debug_label(&self) -> String {
        format!("vfio {} device", self.device.device_name())
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        self.read_mmio(info.address, data)
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        self.write_mmio(info.address, data)
    }
}

impl BusDeviceObj for VfioPlatformDevice {
    fn as_platform_device(&self) -> Option<&VfioPlatformDevice> {
        Some(self)
    }
    fn as_platform_device_mut(&mut self) -> Option<&mut VfioPlatformDevice> {
        Some(self)
    }
    fn into_platform_device(self: Box<Self>) -> Option<Box<VfioPlatformDevice>> {
        Some(self)
    }
}

impl VfioPlatformDevice {
    /// Constructs a new Vfio Platform device for the given Vfio device
    pub fn new(device: VfioDevice, vfio_device_socket_mem: Tube) -> Self {
        let dev = Arc::new(device);
        VfioPlatformDevice {
            device: dev,
            interrupt_edge_evt: Vec::new(),
            interrupt_level_evt: Vec::new(),
            mmio_regions: Vec::new(),
            vm_socket_mem: vfio_device_socket_mem,
            mem: Vec::new(),
        }
    }

    pub fn get_platform_irqs(&self) -> Result<Vec<VfioIrq>, VfioError> {
        self.device.get_irqs()
    }

    pub fn irq_is_automask(&self, irq: &VfioIrq) -> bool {
        irq.flags & VFIO_IRQ_INFO_AUTOMASKED != 0
    }

    fn setup_irq_resample(&mut self, resample_evt: &Event, index: u32) -> Result<()> {
        self.device.irq_mask(index).context("Intx mask failed")?;
        self.device
            .resample_virq_enable(resample_evt, index)
            .context("resample enable failed")?;
        self.device
            .irq_unmask(index)
            .context("Intx unmask failed")?;
        Ok(())
    }

    pub fn assign_edge_platform_irq(&mut self, irq_evt: &IrqEdgeEvent, index: u32) -> Result<()> {
        let interrupt_evt = irq_evt.try_clone().context("failed to clone irq event")?;
        self.device
            .irq_enable(&[Some(interrupt_evt.get_trigger())], index, 0)
            .context("platform irq enable failed")?;
        self.interrupt_edge_evt.push(interrupt_evt);
        Ok(())
    }

    pub fn assign_level_platform_irq(&mut self, irq_evt: &IrqLevelEvent, index: u32) -> Result<()> {
        let interrupt_evt = irq_evt.try_clone().context("failed to clone irq event")?;
        self.device
            .irq_enable(&[Some(interrupt_evt.get_trigger())], index, 0)
            .context("platform irq enable failed")?;
        if let Err(e) = self.setup_irq_resample(interrupt_evt.get_resample(), index) {
            self.disable_irqs(index);
            bail!("failed to set up irq resampling: {}", e);
        }
        self.interrupt_level_evt.push(interrupt_evt);
        Ok(())
    }

    fn find_region(&self, addr: u64) -> Option<MmioInfo> {
        for mmio_info in self.mmio_regions.iter() {
            if addr >= mmio_info.start && addr < mmio_info.start + mmio_info.length {
                return Some(MmioInfo {
                    index: mmio_info.index,
                    start: mmio_info.start,
                    length: mmio_info.length,
                });
            }
        }
        None
    }

    pub fn allocate_regions(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>, resources::Error> {
        let mut ranges = Vec::new();
        for i in 0..self.device.get_region_count() {
            let size = self.device.get_region_size(i);
            let alloc_id = resources.get_anon_alloc();
            let allocator = resources
                .mmio_platform_allocator()
                .ok_or(resources::Error::MissingPlatformMMIOAddresses)?;
            let start_addr = allocator.allocate_with_align(
                size,
                alloc_id,
                "vfio_mmio".to_string(),
                pagesize() as u64,
            )?;
            ranges.push((start_addr, size));

            self.mmio_regions.push(MmioInfo {
                index: i,
                start: start_addr,
                length: size,
            });
        }
        Ok(ranges)
    }

    fn region_mmap(&self, index: u32, start_addr: u64) -> Vec<MemoryMapping> {
        let mut mem_map: Vec<MemoryMapping> = Vec::new();
        if self.device.get_region_flags(index) & VFIO_REGION_INFO_FLAG_MMAP != 0 {
            let mmaps = self.device.get_region_mmap(index);
            if mmaps.is_empty() {
                return mem_map;
            }

            for mmap in mmaps.iter() {
                let mmap_offset = mmap.offset;
                let mmap_size = mmap.size;
                let guest_map_start = start_addr + mmap_offset;
                let region_offset = self.device.get_region_offset(index);
                let offset = region_offset + mmap_offset;
                let descriptor = match self.device.device_file().try_clone() {
                    Ok(device_file) => device_file.into(),
                    Err(_) => break,
                };
                if self
                    .vm_socket_mem
                    .send(&VmMemoryRequest::RegisterMemory {
                        source: VmMemorySource::Descriptor {
                            descriptor,
                            offset,
                            size: mmap_size,
                        },
                        dest: VmMemoryDestination::GuestPhysicalAddress(guest_map_start),
                        read_only: false,
                    })
                    .is_err()
                {
                    break;
                }

                let response: VmMemoryResponse = match self.vm_socket_mem.recv() {
                    Ok(res) => res,
                    Err(_) => break,
                };
                match response {
                    VmMemoryResponse::Ok => {
                        // Even if vm has mapped this region, but it is in vm main process,
                        // device process doesn't has this mapping, but vfio_dma_map() need it
                        // in device process, so here map it again.
                        let mmap = match MemoryMappingBuilder::new(mmap_size as usize)
                            .from_file(self.device.device_file())
                            .offset(offset)
                            .build()
                        {
                            Ok(v) => v,
                            Err(_e) => break,
                        };
                        let host = (&mmap).as_ptr() as u64;
                        // Safe because the given guest_map_start is valid guest bar address. and
                        // the host pointer is correct and valid guaranteed by MemoryMapping interface.
                        match unsafe {
                            self.device
                                .vfio_dma_map(guest_map_start, mmap_size, host, true)
                        } {
                            Ok(_) => mem_map.push(mmap),
                            Err(e) => {
                                error!(
                                    "{}, index: {}, start_addr:0x{:x}, host:0x{:x}",
                                    e, index, start_addr, host
                                );
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }
        }

        mem_map
    }

    fn regions_mmap(&mut self) {
        for mmio_info in self.mmio_regions.iter() {
            let mut mem_map = self.region_mmap(mmio_info.index, mmio_info.start);
            self.mem.append(&mut mem_map);
        }
    }

    fn disable_irqs(&mut self, index: u32) {
        if let Err(e) = self.device.irq_disable(index) {
            error!("Platform irq disable failed: {}", e);
        }
    }

    fn read_mmio(&mut self, addr: u64, data: &mut [u8]) {
        if let Some(mmio_info) = self.find_region(addr) {
            let offset = addr - mmio_info.start;
            let index = mmio_info.index;
            self.device.region_read(index, data, offset);
        }
        // We have no other way than wait for 1st access and then do the mmap,
        // so that next accesses are dual-stage MMU accelerated.
        self.regions_mmap();
    }

    fn write_mmio(&mut self, addr: u64, data: &[u8]) {
        if let Some(mmio_info) = self.find_region(addr) {
            let offset = addr - mmio_info.start;
            let index = mmio_info.index;
            self.device.region_write(index, data, offset);
        }
        // We have no other way than wait for 1st access and then do the mmap,
        // so that next accesses are dual-stage MMU accelerated.
        self.regions_mmap();
    }

    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = self.device.keep_rds();

        for irq_evt in self.interrupt_edge_evt.iter() {
            rds.extend(irq_evt.as_raw_descriptors());
        }

        for irq_evt in self.interrupt_level_evt.iter() {
            rds.extend(irq_evt.as_raw_descriptors());
        }

        rds.push(self.vm_socket_mem.as_raw_descriptor());
        rds
    }

    /// Gets the vfio device backing `File`.
    pub fn device_file(&self) -> &File {
        self.device.device_file()
    }
}
