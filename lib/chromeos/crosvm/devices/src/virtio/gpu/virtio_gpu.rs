// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap as Map;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::result::Result;
use std::sync::Arc;

use crate::virtio::gpu::GpuDisplayParameters;
use crate::virtio::resource_bridge::{BufferInfo, PlaneInfo, ResourceInfo, ResourceResponse};
use base::{error, ExternalMapping, SafeDescriptor, Tube};

use data_model::VolatileSlice;

use gpu_display::*;
use rutabaga_gfx::{
    ResourceCreate3D, ResourceCreateBlob, Rutabaga, RutabagaBuilder, RutabagaFence,
    RutabagaFenceHandler, RutabagaIovec, Transfer3D,
};

use libc::c_void;

use resources::Alloc;

use super::protocol::{
    GpuResponse::{self, *},
    GpuResponsePlaneInfo, VirtioGpuResult, VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE,
    VIRTIO_GPU_BLOB_MEM_HOST3D,
};
use super::udmabuf::UdmabufDriver;
use super::VirtioScanoutBlobData;
use sync::Mutex;

use vm_memory::{GuestAddress, GuestMemory};

use vm_control::{MemSlot, VmMemoryDestination, VmMemoryRequest, VmMemoryResponse, VmMemorySource};

struct VirtioGpuResource {
    resource_id: u32,
    width: u32,
    height: u32,
    size: u64,
    slot: Option<MemSlot>,
    scanout_data: Option<VirtioScanoutBlobData>,
    display_import: Option<u32>,
}

impl VirtioGpuResource {
    /// Creates a new VirtioGpuResource with the given metadata.  Width and height are used by the
    /// display, while size is useful for hypervisor mapping.
    pub fn new(resource_id: u32, width: u32, height: u32, size: u64) -> VirtioGpuResource {
        VirtioGpuResource {
            resource_id,
            width,
            height,
            size,
            slot: None,
            scanout_data: None,
            display_import: None,
        }
    }
}

struct VirtioGpuScanout {
    width: u32,
    height: u32,
    surface_id: Option<u32>,
    resource_id: Option<NonZeroU32>,
    scanout_type: SurfaceType,
    // If this scanout is a primary scanout, the scanout id.
    scanout_id: Option<u32>,
    // If this scanout is a cursor scanout, the scanout that this is cursor is overlayed onto.
    parent_surface_id: Option<u32>,
}

impl VirtioGpuScanout {
    fn new(width: u32, height: u32, scanout_id: u32) -> VirtioGpuScanout {
        VirtioGpuScanout {
            width,
            height,
            scanout_type: SurfaceType::Scanout,
            scanout_id: Some(scanout_id),
            surface_id: None,
            resource_id: None,
            parent_surface_id: None,
        }
    }

    fn new_cursor() -> VirtioGpuScanout {
        // Per virtio spec: "The mouse cursor image is a normal resource, except that it must be
        // 64x64 in size."
        VirtioGpuScanout {
            width: 64,
            height: 64,
            scanout_type: SurfaceType::Cursor,
            scanout_id: None,
            surface_id: None,
            resource_id: None,
            parent_surface_id: None,
        }
    }

    fn create_surface(
        &mut self,
        display: &Rc<RefCell<GpuDisplay>>,
        new_parent_surface_id: Option<u32>,
    ) -> VirtioGpuResult {
        let mut need_to_create = false;

        if self.surface_id.is_none() {
            need_to_create = true;
        }

        if self.parent_surface_id != new_parent_surface_id {
            self.parent_surface_id = new_parent_surface_id;
            need_to_create = true;
        }

        if !need_to_create {
            return Ok(OkNoData);
        }

        self.release_surface(display);

        let mut display = display.borrow_mut();

        let surface_id = display.create_surface(
            self.parent_surface_id,
            self.width,
            self.height,
            self.scanout_type,
        )?;

        if let Some(scanout_id) = self.scanout_id {
            display.set_scanout_id(surface_id, scanout_id)?;
        }

        self.surface_id = Some(surface_id);

        Ok(OkNoData)
    }

    fn release_surface(&mut self, display: &Rc<RefCell<GpuDisplay>>) {
        if let Some(surface_id) = self.surface_id {
            display.borrow_mut().release_surface(surface_id);
        }

        self.surface_id = None;
    }

    fn set_position(&self, display: &Rc<RefCell<GpuDisplay>>, x: u32, y: u32) -> VirtioGpuResult {
        if let Some(surface_id) = self.surface_id {
            display.borrow_mut().set_position(surface_id, x, y)?;
        }
        Ok(OkNoData)
    }

    fn commit(&self, display: &Rc<RefCell<GpuDisplay>>) -> VirtioGpuResult {
        if let Some(surface_id) = self.surface_id {
            display.borrow_mut().commit(surface_id)?;
        }
        Ok(OkNoData)
    }

    fn flush(
        &mut self,
        display: &Rc<RefCell<GpuDisplay>>,
        resource: &mut VirtioGpuResource,
        rutabaga: &mut Rutabaga,
    ) -> VirtioGpuResult {
        let surface_id = match self.surface_id {
            Some(id) => id,
            _ => return Ok(OkNoData),
        };

        if let Some(import_id) =
            VirtioGpuScanout::import_resource_to_display(display, resource, rutabaga)
        {
            display.borrow_mut().flip_to(surface_id, import_id)?;
            return Ok(OkNoData);
        }

        // Import failed, fall back to a copy.
        let mut display = display.borrow_mut();

        // Prevent overwriting a buffer that is currently being used by the compositor.
        if display.next_buffer_in_use(surface_id) {
            return Ok(OkNoData);
        }

        let fb = display
            .framebuffer_region(surface_id, 0, 0, self.width, self.height)
            .ok_or(ErrUnspec)?;

        let mut transfer = Transfer3D::new_2d(0, 0, self.width, self.height);
        transfer.stride = fb.stride();
        rutabaga.transfer_read(
            0,
            resource.resource_id,
            transfer,
            Some(fb.as_volatile_slice()),
        )?;

        display.flip(surface_id);
        Ok(OkNoData)
    }

    fn import_resource_to_display(
        display: &Rc<RefCell<GpuDisplay>>,
        resource: &mut VirtioGpuResource,
        rutabaga: &mut Rutabaga,
    ) -> Option<u32> {
        if let Some(import_id) = resource.display_import {
            return Some(import_id);
        }

        let dmabuf = rutabaga.export_blob(resource.resource_id).ok()?;
        let query = rutabaga.query(resource.resource_id).ok()?;

        let (width, height, format, stride, offset) = match resource.scanout_data {
            Some(data) => (
                data.width,
                data.height,
                data.drm_format.into(),
                data.strides[0],
                data.offsets[0],
            ),
            None => (
                resource.width,
                resource.height,
                query.drm_fourcc,
                query.strides[0],
                query.offsets[0],
            ),
        };

        let import_id = display
            .borrow_mut()
            .import_memory(
                &dmabuf.os_handle,
                offset,
                stride,
                query.modifier,
                width,
                height,
                format,
            )
            .ok()?;
        resource.display_import = Some(import_id);
        Some(import_id)
    }
}

/// Handles functionality related to displays, input events and hypervisor memory management.
pub struct VirtioGpu {
    display: Rc<RefCell<GpuDisplay>>,
    scanouts: Vec<VirtioGpuScanout>,
    cursor_scanout: VirtioGpuScanout,
    // Maps event devices to scanout number.
    event_devices: Map<u32, u32>,
    gpu_device_tube: Tube,
    pci_bar: Alloc,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    rutabaga: Rutabaga,
    resources: Map<u32, VirtioGpuResource>,
    external_blob: bool,
    udmabuf_driver: Option<UdmabufDriver>,
}

fn sglist_to_rutabaga_iovecs(
    vecs: &[(GuestAddress, usize)],
    mem: &GuestMemory,
) -> Result<Vec<RutabagaIovec>, ()> {
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice_at_addr(addr, len).is_err())
    {
        return Err(());
    }

    let mut rutabaga_iovecs: Vec<RutabagaIovec> = Vec::new();
    for &(addr, len) in vecs {
        let slice = mem.get_slice_at_addr(addr, len).unwrap();
        rutabaga_iovecs.push(RutabagaIovec {
            base: slice.as_mut_ptr() as *mut c_void,
            len,
        });
    }
    Ok(rutabaga_iovecs)
}

impl VirtioGpu {
    /// Creates a new instance of the VirtioGpu state tracker.
    pub fn new(
        display: GpuDisplay,
        display_params: Vec<GpuDisplayParameters>,
        rutabaga_builder: RutabagaBuilder,
        event_devices: Vec<EventDevice>,
        gpu_device_tube: Tube,
        pci_bar: Alloc,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        external_blob: bool,
        udmabuf: bool,
        fence_handler: RutabagaFenceHandler,
        render_server_fd: Option<SafeDescriptor>,
    ) -> Option<VirtioGpu> {
        let rutabaga = rutabaga_builder
            .build(fence_handler, render_server_fd)
            .map_err(|e| error!("failed to build rutabaga {}", e))
            .ok()?;

        let mut udmabuf_driver = None;
        if udmabuf {
            udmabuf_driver = Some(
                UdmabufDriver::new()
                    .map_err(|e| error!("failed to initialize udmabuf: {}", e))
                    .ok()?,
            );
        }

        let scanouts = display_params
            .iter()
            .enumerate()
            .map(|(display_index, &display_param)| {
                VirtioGpuScanout::new(
                    display_param.width,
                    display_param.height,
                    display_index as u32,
                )
            })
            .collect::<Vec<_>>();
        let cursor_scanout = VirtioGpuScanout::new_cursor();

        let mut virtio_gpu = VirtioGpu {
            display: Rc::new(RefCell::new(display)),
            scanouts,
            cursor_scanout,
            event_devices: Default::default(),
            gpu_device_tube,
            pci_bar,
            map_request,
            rutabaga,
            resources: Default::default(),
            external_blob,
            udmabuf_driver,
        };

        for event_device in event_devices {
            virtio_gpu
                .import_event_device(event_device, 0)
                .map_err(|e| error!("failed to import event device {}", e))
                .ok()?;
        }

        Some(virtio_gpu)
    }

    /// Imports the event device
    pub fn import_event_device(
        &mut self,
        event_device: EventDevice,
        scanout_id: u32,
    ) -> VirtioGpuResult {
        let mut display = self.display.borrow_mut();
        let event_device_id = display.import_event_device(event_device)?;
        self.event_devices.insert(event_device_id, scanout_id);
        Ok(OkNoData)
    }

    /// Gets a reference to the display passed into `new`.
    pub fn display(&mut self) -> &Rc<RefCell<GpuDisplay>> {
        &self.display
    }

    /// Gets the list of supported display resolutions as a slice of `(width, height)` tuples.
    pub fn display_info(&self) -> Vec<(u32, u32)> {
        self.scanouts
            .iter()
            .map(|scanout| (scanout.width, scanout.height))
            .collect::<Vec<_>>()
    }

    /// Processes the internal `display` events and returns `true` if any display was closed.
    pub fn process_display(&mut self) -> bool {
        let mut display = self.display.borrow_mut();
        let result = display.dispatch_events();
        match result {
            Ok(_) => (),
            Err(e) => error!("failed to dispatch events: {}", e),
        }

        for scanout in &self.scanouts {
            let close_requested = scanout
                .surface_id
                .map(|surface_id| display.close_requested(surface_id))
                .unwrap_or(false);

            if close_requested {
                return true;
            }
        }

        false
    }

    /// Sets the given resource id as the source of scanout to the display.
    pub fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        scanout_data: Option<VirtioScanoutBlobData>,
    ) -> VirtioGpuResult {
        self.update_scanout_resource(SurfaceType::Scanout, scanout_id, scanout_data, resource_id)
    }

    /// If the resource is the scanout resource, flush it to the display.
    pub fn flush_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        // `resource_id` has already been verified to be non-zero
        let resource_id = match NonZeroU32::new(resource_id) {
            Some(id) => Some(id),
            None => return Ok(OkNoData),
        };

        for scanout in &mut self.scanouts {
            if scanout.resource_id == resource_id {
                scanout.flush(&self.display, resource, &mut self.rutabaga)?;
            }
        }
        if self.cursor_scanout.resource_id == resource_id {
            self.cursor_scanout
                .flush(&self.display, resource, &mut self.rutabaga)?;
        }

        Ok(OkNoData)
    }

    /// Updates the cursor's memory to the given resource_id, and sets its position to the given
    /// coordinates.
    pub fn update_cursor(
        &mut self,
        resource_id: u32,
        scanout_id: u32,
        x: u32,
        y: u32,
    ) -> VirtioGpuResult {
        self.update_scanout_resource(SurfaceType::Cursor, scanout_id, None, resource_id)?;

        self.cursor_scanout.set_position(&self.display, x, y)?;

        self.flush_resource(resource_id)
    }

    /// Moves the cursor's position to the given coordinates.
    pub fn move_cursor(&mut self, _scanout_id: u32, x: u32, y: u32) -> VirtioGpuResult {
        self.cursor_scanout.set_position(&self.display, x, y)?;
        self.cursor_scanout.commit(&self.display)?;
        Ok(OkNoData)
    }

    /// Returns a uuid for the resource.
    pub fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult {
        if !self.resources.contains_key(&resource_id) {
            return Err(ErrInvalidResourceId);
        }

        // TODO(stevensd): use real uuids once the virtio wayland protocol is updated to
        // handle more than 32 bits. For now, the virtwl driver knows that the uuid is
        // actually just the resource id.
        let mut uuid: [u8; 16] = [0; 16];
        for (idx, byte) in resource_id.to_be_bytes().iter().enumerate() {
            uuid[12 + idx] = *byte;
        }
        Ok(OkResourceUuid { uuid })
    }

    /// If supported, export the resource with the given `resource_id` to a file.
    pub fn export_resource(&mut self, resource_id: u32) -> ResourceResponse {
        let file = match self.rutabaga.export_blob(resource_id) {
            Ok(handle) => handle.os_handle.into(),
            Err(_) => return ResourceResponse::Invalid,
        };

        let q = match self.rutabaga.query(resource_id) {
            Ok(query) => query,
            Err(_) => return ResourceResponse::Invalid,
        };

        ResourceResponse::Resource(ResourceInfo::Buffer(BufferInfo {
            file,
            planes: [
                PlaneInfo {
                    offset: q.offsets[0],
                    stride: q.strides[0],
                },
                PlaneInfo {
                    offset: q.offsets[1],
                    stride: q.strides[1],
                },
                PlaneInfo {
                    offset: q.offsets[2],
                    stride: q.strides[2],
                },
                PlaneInfo {
                    offset: q.offsets[3],
                    stride: q.strides[3],
                },
            ],
            modifier: q.modifier,
        }))
    }

    /// If supported, export the fence with the given `fence_id` to a file.
    pub fn export_fence(&self, fence_id: u32) -> ResourceResponse {
        match self.rutabaga.export_fence(fence_id) {
            Ok(handle) => ResourceResponse::Resource(ResourceInfo::Fence {
                file: handle.os_handle.into(),
            }),
            Err(_) => ResourceResponse::Invalid,
        }
    }

    /// Gets rutabaga's capset information associated with `index`.
    pub fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        let (capset_id, version, size) = self.rutabaga.get_capset_info(index)?;
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    /// Gets a capset from rutabaga.
    pub fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = self.rutabaga.get_capset(capset_id, version)?;
        Ok(OkCapset(capset))
    }

    /// Forces rutabaga to use it's default context.
    pub fn force_ctx_0(&self) {
        self.rutabaga.force_ctx_0()
    }

    /// Creates a fence with the RutabagaFence that can be used to determine when the previous
    /// command completed.
    pub fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        self.rutabaga.create_fence(rutabaga_fence)?;
        Ok(OkNoData)
    }

    /// Polls the Rutabaga backend.
    pub fn poll(&self) {
        self.rutabaga.poll();
    }

    /// Gets a pollable eventfd that signals the device to wakeup and poll the
    /// Rutabaga backend.
    pub fn poll_descriptor(&self) -> Option<SafeDescriptor> {
        self.rutabaga.poll_descriptor()
    }

    /// Creates a 3D resource with the given properties and resource_id.
    pub fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .resource_create_3d(resource_id, resource_create_3d)?;

        let resource = VirtioGpuResource::new(
            resource_id,
            resource_create_3d.width,
            resource_create_3d.height,
            0,
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space. Converts to RutabageIovec from the memory
    /// mapping.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?;
        self.rutabaga.attach_backing(resource_id, rutabaga_iovecs)?;
        Ok(OkNoData)
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.detach_backing(resource_id)?;
        Ok(OkNoData)
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.resources
            .remove(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        self.rutabaga.unref_resource(resource_id)?;
        Ok(OkNoData)
    }

    /// Copies data to host resource from the attached iovecs. Can also be used to flush caches.
    pub fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .transfer_write(ctx_id, resource_id, transfer)?;
        Ok(OkNoData)
    }

    /// Copies data from the host resource to:
    ///    1) To the optional volatile slice
    ///    2) To the host resource's attached iovecs
    ///
    /// Can also be used to invalidate caches.
    pub fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        self.rutabaga
            .transfer_read(ctx_id, resource_id, transfer, buf)?;
        Ok(OkNoData)
    }

    /// Creates a blob resource using rutabaga.
    pub fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemory,
    ) -> VirtioGpuResult {
        let mut rutabaga_handle = None;
        let mut rutabaga_iovecs = None;

        if resource_create_blob.blob_flags & VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE != 0 {
            rutabaga_handle = match self.udmabuf_driver {
                Some(ref driver) => Some(driver.create_udmabuf(mem, &vecs[..])?),
                None => return Err(ErrUnspec),
            }
        } else if resource_create_blob.blob_mem != VIRTIO_GPU_BLOB_MEM_HOST3D {
            rutabaga_iovecs =
                Some(sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?);
        }

        self.rutabaga.resource_create_blob(
            ctx_id,
            resource_id,
            resource_create_blob,
            rutabaga_iovecs,
            rutabaga_handle,
        )?;

        let resource = VirtioGpuResource::new(resource_id, 0, 0, resource_create_blob.size);

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Uses the hypervisor to map the rutabaga blob resource.
    pub fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;
        let vulkan_info_opt = self.rutabaga.vulkan_info(resource_id).ok();

        let source = if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            match vulkan_info_opt {
                Some(vulkan_info) => VmMemorySource::Vulkan {
                    descriptor: export.os_handle,
                    handle_type: export.handle_type,
                    memory_idx: vulkan_info.memory_idx,
                    physical_device_idx: vulkan_info.physical_device_idx,
                    size: resource.size,
                },
                None => VmMemorySource::Descriptor {
                    descriptor: export.os_handle,
                    offset: 0,
                    size: resource.size,
                },
            }
        } else {
            if self.external_blob {
                return Err(ErrUnspec);
            }

            let mapping = self.rutabaga.map(resource_id)?;
            // Scope for lock
            {
                let mut map_req = self.map_request.lock();
                if map_req.is_some() {
                    return Err(ErrUnspec);
                }
                *map_req = Some(mapping);
            }
            VmMemorySource::ExternalMapping {
                size: resource.size,
            }
        };

        let request = VmMemoryRequest::RegisterMemory {
            source,
            dest: VmMemoryDestination::ExistingAllocation {
                allocation: self.pci_bar,
                offset,
            },
            read_only: false,
        };
        self.gpu_device_tube.send(&request)?;
        let response = self.gpu_device_tube.recv()?;

        match response {
            VmMemoryResponse::RegisterMemory { pfn: _, slot } => {
                resource.slot = Some(slot);
                Ok(OkMapInfo { map_info })
            }
            VmMemoryResponse::Err(e) => Err(ErrBase(e)),
            _ => Err(ErrUnspec),
        }
    }

    /// Uses the hypervisor to unmap the blob resource.
    pub fn resource_unmap_blob(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let slot = resource.slot.ok_or(ErrUnspec)?;
        let request = VmMemoryRequest::UnregisterMemory(slot);
        self.gpu_device_tube.send(&request)?;
        let response = self.gpu_device_tube.recv()?;

        match response {
            VmMemoryResponse::Ok => {
                resource.slot = None;
                Ok(OkNoData)
            }
            VmMemoryResponse::Err(e) => Err(ErrBase(e)),
            _ => Err(ErrUnspec),
        }
    }

    /// Creates a rutabaga context.
    pub fn create_context(&mut self, ctx_id: u32, context_init: u32) -> VirtioGpuResult {
        self.rutabaga.create_context(ctx_id, context_init)?;
        Ok(OkNoData)
    }

    /// Destroys a rutabaga context.
    pub fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        self.rutabaga.destroy_context(ctx_id)?;
        Ok(OkNoData)
    }

    /// Attaches a resource to a rutabaga context.
    pub fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_attach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Detaches a resource from a rutabaga context.
    pub fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_detach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Submits a command buffer to a rutabaga context.
    pub fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> VirtioGpuResult {
        self.rutabaga.submit_command(ctx_id, commands)?;
        Ok(OkNoData)
    }

    // Non-public function -- no doc comment needed!
    fn result_from_query(&mut self, resource_id: u32) -> GpuResponse {
        match self.rutabaga.query(resource_id) {
            Ok(query) => {
                let mut plane_info = Vec::with_capacity(4);
                for plane_index in 0..4 {
                    plane_info.push(GpuResponsePlaneInfo {
                        stride: query.strides[plane_index],
                        offset: query.offsets[plane_index],
                    });
                }
                let format_modifier = query.modifier;
                OkResourcePlaneInfo {
                    format_modifier,
                    plane_info,
                }
            }
            Err(_) => OkNoData,
        }
    }

    fn update_scanout_resource(
        &mut self,
        scanout_type: SurfaceType,
        scanout_id: u32,
        scanout_data: Option<VirtioScanoutBlobData>,
        resource_id: u32,
    ) -> VirtioGpuResult {
        let mut scanout: &mut VirtioGpuScanout;
        let mut scanout_parent_surface_id = None;

        match scanout_type {
            SurfaceType::Cursor => {
                let parent_scanout_id = scanout_id;

                scanout_parent_surface_id = self
                    .scanouts
                    .get(parent_scanout_id as usize)
                    .ok_or(ErrInvalidScanoutId)
                    .map(|parent_scanout| parent_scanout.surface_id)?;

                scanout = &mut self.cursor_scanout;
            }
            SurfaceType::Scanout => {
                scanout = self
                    .scanouts
                    .get_mut(scanout_id as usize)
                    .ok_or(ErrInvalidScanoutId)?;
            }
        };

        // Virtio spec: "The driver can use resource_id = 0 to disable a scanout."
        if resource_id == 0 {
            // Ignore any initial set_scanout(..., resource_id: 0) calls.
            if scanout.resource_id.is_some() {
                scanout.release_surface(&self.display);
            }

            scanout.resource_id = None;
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        // Ensure scanout has a display surface.
        match scanout_type {
            SurfaceType::Cursor => {
                if let Some(scanout_parent_surface_id) = scanout_parent_surface_id {
                    scanout.create_surface(&self.display, Some(scanout_parent_surface_id))?;
                }
            }
            SurfaceType::Scanout => {
                scanout.create_surface(&self.display, None)?;
            }
        }

        resource.scanout_data = scanout_data;

        // `resource_id` has already been verified to be non-zero
        let resource_id = match NonZeroU32::new(resource_id) {
            Some(id) => id,
            None => return Ok(OkNoData),
        };
        scanout.resource_id = Some(resource_id);

        Ok(OkNoData)
    }
}
