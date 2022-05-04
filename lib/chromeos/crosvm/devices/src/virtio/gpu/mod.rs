// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod protocol;
mod udmabuf;
mod udmabuf_bindings;
mod virtio_gpu;

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryFrom;
use std::io::Read;
use std::mem::{self, size_of};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;

use anyhow::Context;

use base::{
    debug, error, warn, AsRawDescriptor, Event, ExternalMapping, PollToken, RawDescriptor,
    SafeDescriptor, Tube, WaitContext,
};

use data_model::*;

pub use gpu_display::EventDevice;
use gpu_display::*;
use rutabaga_gfx::*;

use resources::Alloc;

use serde::{Deserialize, Serialize};
use sync::Mutex;
use vm_memory::{GuestAddress, GuestMemory};

use super::{
    copy_config, resource_bridge::*, DescriptorChain, Interrupt, Queue, Reader,
    SignalableInterrupt, VirtioDevice, Writer, TYPE_GPU,
};

use super::{PciCapabilityType, VirtioPciShmCap};

use self::protocol::*;
pub use self::protocol::{
    virtio_gpu_config, VIRTIO_GPU_F_CONTEXT_INIT, VIRTIO_GPU_F_CREATE_GUEST_HANDLE,
    VIRTIO_GPU_F_EDID, VIRTIO_GPU_F_RESOURCE_BLOB, VIRTIO_GPU_F_RESOURCE_SYNC,
    VIRTIO_GPU_F_RESOURCE_UUID, VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_SHM_ID_HOST_VISIBLE,
};
use self::virtio_gpu::VirtioGpu;

use crate::pci::{
    PciAddress, PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability,
};

pub const DEFAULT_DISPLAY_WIDTH: u32 = 1280;
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1024;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum GpuMode {
    Mode2D,
    ModeVirglRenderer,
    ModeGfxstream,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct GpuDisplayParameters {
    pub width: u32,
    pub height: u32,
}

impl Default for GpuDisplayParameters {
    fn default() -> Self {
        GpuDisplayParameters {
            width: DEFAULT_DISPLAY_WIDTH,
            height: DEFAULT_DISPLAY_HEIGHT,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GpuParameters {
    pub displays: Vec<GpuDisplayParameters>,
    pub renderer_use_egl: bool,
    pub renderer_use_gles: bool,
    pub renderer_use_glx: bool,
    pub renderer_use_surfaceless: bool,
    pub gfxstream_use_guest_angle: bool,
    pub gfxstream_use_syncfd: bool,
    pub use_vulkan: bool,
    pub udmabuf: bool,
    pub mode: GpuMode,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
}

// First queue is for virtio gpu commands. Second queue is for cursor commands, which we expect
// there to be fewer of.
pub const QUEUE_SIZES: &[u16] = &[256, 16];

pub const GPU_BAR_NUM: u8 = 4;
pub const GPU_BAR_OFFSET: u64 = 0;
pub const GPU_BAR_SIZE: u64 = 1 << 33;

impl Default for GpuParameters {
    fn default() -> Self {
        GpuParameters {
            displays: vec![],
            renderer_use_egl: true,
            renderer_use_gles: true,
            renderer_use_glx: false,
            renderer_use_surfaceless: true,
            gfxstream_use_guest_angle: false,
            gfxstream_use_syncfd: true,
            use_vulkan: false,
            mode: if cfg!(feature = "virgl_renderer") {
                GpuMode::ModeVirglRenderer
            } else {
                GpuMode::Mode2D
            },
            cache_path: None,
            cache_size: None,
            udmabuf: false,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct VirtioScanoutBlobData {
    pub width: u32,
    pub height: u32,
    pub drm_format: DrmFormat,
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum VirtioGpuRing {
    Global,
    ContextSpecific { ctx_id: u32, ring_idx: u8 },
}

struct FenceDescriptor {
    ring: VirtioGpuRing,
    fence_id: u64,
    index: u16,
    len: u32,
}

#[derive(Default)]
pub struct FenceState {
    descs: Vec<FenceDescriptor>,
    completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

pub trait QueueReader {
    fn pop(&self, mem: &GuestMemory) -> Option<DescriptorChain>;
    fn add_used(&self, mem: &GuestMemory, desc_index: u16, len: u32);
    fn signal_used(&self, mem: &GuestMemory);
}

struct LocalQueueReader {
    queue: RefCell<Queue>,
    interrupt: Arc<Interrupt>,
}

impl LocalQueueReader {
    fn new(queue: Queue, interrupt: &Arc<Interrupt>) -> Self {
        Self {
            queue: RefCell::new(queue),
            interrupt: interrupt.clone(),
        }
    }
}

impl QueueReader for LocalQueueReader {
    fn pop(&self, mem: &GuestMemory) -> Option<DescriptorChain> {
        self.queue.borrow_mut().pop(mem)
    }

    fn add_used(&self, mem: &GuestMemory, desc_index: u16, len: u32) {
        self.queue.borrow_mut().add_used(mem, desc_index, len)
    }

    fn signal_used(&self, mem: &GuestMemory) {
        self.queue
            .borrow_mut()
            .trigger_interrupt(mem, &*self.interrupt);
    }
}

#[derive(Clone)]
struct SharedQueueReader {
    queue: Arc<Mutex<Queue>>,
    interrupt: Arc<Interrupt>,
}

impl SharedQueueReader {
    fn new(queue: Queue, interrupt: &Arc<Interrupt>) -> Self {
        Self {
            queue: Arc::new(Mutex::new(queue)),
            interrupt: interrupt.clone(),
        }
    }
}

impl QueueReader for SharedQueueReader {
    fn pop(&self, mem: &GuestMemory) -> Option<DescriptorChain> {
        self.queue.lock().pop(mem)
    }

    fn add_used(&self, mem: &GuestMemory, desc_index: u16, len: u32) {
        self.queue.lock().add_used(mem, desc_index, len)
    }

    fn signal_used(&self, mem: &GuestMemory) {
        self.queue.lock().trigger_interrupt(mem, &*self.interrupt);
    }
}

/// Initializes the virtio_gpu state tracker.
fn build(
    display_backends: &[DisplayBackend],
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
    let mut display_opt = None;
    for display_backend in display_backends {
        match display_backend.build() {
            Ok(c) => {
                display_opt = Some(c);
                break;
            }
            Err(e) => error!("failed to open display: {}", e),
        };
    }

    let display = match display_opt {
        Some(d) => d,
        None => {
            error!("failed to open any displays");
            return None;
        }
    };

    VirtioGpu::new(
        display,
        display_params,
        rutabaga_builder,
        event_devices,
        gpu_device_tube,
        pci_bar,
        map_request,
        external_blob,
        udmabuf,
        fence_handler,
        render_server_fd,
    )
}

/// Create a handler that writes into the completed fence queue
pub fn create_fence_handler<Q>(
    mem: GuestMemory,
    ctrl_queue: Q,
    fence_state: Arc<Mutex<FenceState>>,
) -> RutabagaFenceHandler
where
    Q: QueueReader + Send + Clone + 'static,
{
    RutabagaFenceClosure::new(move |completed_fence| {
        let mut signal = false;

        {
            let ring = match completed_fence.flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                0 => VirtioGpuRing::Global,
                _ => VirtioGpuRing::ContextSpecific {
                    ctx_id: completed_fence.ctx_id,
                    ring_idx: completed_fence.ring_idx,
                },
            };

            let mut fence_state = fence_state.lock();
            fence_state.descs.retain(|f_desc| {
                if f_desc.ring == ring && f_desc.fence_id <= completed_fence.fence_id {
                    ctrl_queue.add_used(&mem, f_desc.index, f_desc.len);
                    signal = true;
                    return false;
                }
                true
            });
            // Update the last completed fence for this context
            fence_state
                .completed_fences
                .insert(ring, completed_fence.fence_id);
        }

        if signal {
            ctrl_queue.signal_used(&mem);
        }
    })
}

pub struct ReturnDescriptor {
    pub index: u16,
    pub len: u32,
}

pub struct Frontend {
    fence_state: Arc<Mutex<FenceState>>,
    return_cursor_descriptors: VecDeque<ReturnDescriptor>,
    virtio_gpu: VirtioGpu,
}

impl Frontend {
    fn new(virtio_gpu: VirtioGpu, fence_state: Arc<Mutex<FenceState>>) -> Frontend {
        Frontend {
            fence_state,
            return_cursor_descriptors: Default::default(),
            virtio_gpu,
        }
    }

    /// Returns the internal connection to the compositor and its associated state.
    pub fn display(&mut self) -> &Rc<RefCell<GpuDisplay>> {
        self.virtio_gpu.display()
    }

    /// Processes the internal `display` events and returns `true` if any display was closed.
    pub fn process_display(&mut self) -> bool {
        self.virtio_gpu.process_display()
    }

    /// Processes incoming requests on `resource_bridge`.
    pub fn process_resource_bridge(&mut self, resource_bridge: &Tube) -> anyhow::Result<()> {
        let response = match resource_bridge.recv() {
            Ok(ResourceRequest::GetBuffer { id }) => self.virtio_gpu.export_resource(id),
            Ok(ResourceRequest::GetFence { seqno }) => {
                // The seqno originated from self.backend, so
                // it should fit in a u32.
                match u32::try_from(seqno) {
                    Ok(fence_id) => self.virtio_gpu.export_fence(fence_id),
                    Err(_) => ResourceResponse::Invalid,
                }
            }
            Err(e) => return Err(e).context("Error receiving resource bridge request"),
        };

        resource_bridge
            .send(&response)
            .context("Error sending resource bridge response")?;

        Ok(())
    }

    fn process_gpu_command(
        &mut self,
        mem: &GuestMemory,
        cmd: GpuCommand,
        reader: &mut Reader,
    ) -> VirtioGpuResult {
        self.virtio_gpu.force_ctx_0();

        match cmd {
            GpuCommand::GetDisplayInfo(_) => Ok(GpuResponse::OkDisplayInfo(
                self.virtio_gpu.display_info().to_vec(),
            )),
            GpuCommand::ResourceCreate2d(info) => {
                let resource_id = info.resource_id.to_native();

                let resource_create_3d = ResourceCreate3D {
                    target: RUTABAGA_PIPE_TEXTURE_2D,
                    format: info.format.to_native(),
                    bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                    width: info.width.to_native(),
                    height: info.height.to_native(),
                    depth: 1,
                    array_size: 1,
                    last_level: 0,
                    nr_samples: 0,
                    flags: 0,
                };

                self.virtio_gpu
                    .resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::ResourceUnref(info) => {
                self.virtio_gpu.unref_resource(info.resource_id.to_native())
            }
            GpuCommand::SetScanout(info) => self.virtio_gpu.set_scanout(
                info.scanout_id.to_native(),
                info.resource_id.to_native(),
                None,
            ),
            GpuCommand::ResourceFlush(info) => {
                self.virtio_gpu.flush_resource(info.resource_id.to_native())
            }
            GpuCommand::TransferToHost2d(info) => {
                let resource_id = info.resource_id.to_native();
                let transfer = Transfer3D::new_2d(
                    info.r.x.to_native(),
                    info.r.y.to_native(),
                    info.r.width.to_native(),
                    info.r.height.to_native(),
                );
                self.virtio_gpu.transfer_write(0, resource_id, transfer)
            }
            GpuCommand::ResourceAttachBacking(info) => {
                let available_bytes = reader.available_bytes();
                if available_bytes != 0 {
                    let entry_count = info.nr_entries.to_native() as usize;
                    let mut vecs = Vec::with_capacity(entry_count);
                    for _ in 0..entry_count {
                        match reader.read_obj::<virtio_gpu_mem_entry>() {
                            Ok(entry) => {
                                let addr = GuestAddress(entry.addr.to_native());
                                let len = entry.length.to_native() as usize;
                                vecs.push((addr, len))
                            }
                            Err(_) => return Err(GpuResponse::ErrUnspec),
                        }
                    }
                    self.virtio_gpu
                        .attach_backing(info.resource_id.to_native(), mem, vecs)
                } else {
                    error!("missing data for command {:?}", cmd);
                    Err(GpuResponse::ErrUnspec)
                }
            }
            GpuCommand::ResourceDetachBacking(info) => {
                self.virtio_gpu.detach_backing(info.resource_id.to_native())
            }
            GpuCommand::UpdateCursor(info) => self.virtio_gpu.update_cursor(
                info.resource_id.to_native(),
                info.pos.scanout_id.to_native(),
                info.pos.x.into(),
                info.pos.y.into(),
            ),
            GpuCommand::MoveCursor(info) => self.virtio_gpu.move_cursor(
                info.pos.scanout_id.to_native(),
                info.pos.x.into(),
                info.pos.y.into(),
            ),
            GpuCommand::ResourceAssignUuid(info) => {
                let resource_id = info.resource_id.to_native();
                self.virtio_gpu.resource_assign_uuid(resource_id)
            }
            GpuCommand::GetCapsetInfo(info) => self
                .virtio_gpu
                .get_capset_info(info.capset_index.to_native()),
            GpuCommand::GetCapset(info) => self
                .virtio_gpu
                .get_capset(info.capset_id.to_native(), info.capset_version.to_native()),
            GpuCommand::CtxCreate(info) => self
                .virtio_gpu
                .create_context(info.hdr.ctx_id.to_native(), info.context_init.to_native()),
            GpuCommand::CtxDestroy(info) => {
                self.virtio_gpu.destroy_context(info.hdr.ctx_id.to_native())
            }
            GpuCommand::CtxAttachResource(info) => self
                .virtio_gpu
                .context_attach_resource(info.hdr.ctx_id.to_native(), info.resource_id.to_native()),
            GpuCommand::CtxDetachResource(info) => self
                .virtio_gpu
                .context_detach_resource(info.hdr.ctx_id.to_native(), info.resource_id.to_native()),
            GpuCommand::ResourceCreate3d(info) => {
                let resource_id = info.resource_id.to_native();
                let resource_create_3d = ResourceCreate3D {
                    target: info.target.to_native(),
                    format: info.format.to_native(),
                    bind: info.bind.to_native(),
                    width: info.width.to_native(),
                    height: info.height.to_native(),
                    depth: info.depth.to_native(),
                    array_size: info.array_size.to_native(),
                    last_level: info.last_level.to_native(),
                    nr_samples: info.nr_samples.to_native(),
                    flags: info.flags.to_native(),
                };

                self.virtio_gpu
                    .resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::TransferToHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let resource_id = info.resource_id.to_native();

                let transfer = Transfer3D {
                    x: info.box_.x.to_native(),
                    y: info.box_.y.to_native(),
                    z: info.box_.z.to_native(),
                    w: info.box_.w.to_native(),
                    h: info.box_.h.to_native(),
                    d: info.box_.d.to_native(),
                    level: info.level.to_native(),
                    stride: info.stride.to_native(),
                    layer_stride: info.layer_stride.to_native(),
                    offset: info.offset.to_native(),
                };

                self.virtio_gpu
                    .transfer_write(ctx_id, resource_id, transfer)
            }
            GpuCommand::TransferFromHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let resource_id = info.resource_id.to_native();

                let transfer = Transfer3D {
                    x: info.box_.x.to_native(),
                    y: info.box_.y.to_native(),
                    z: info.box_.z.to_native(),
                    w: info.box_.w.to_native(),
                    h: info.box_.h.to_native(),
                    d: info.box_.d.to_native(),
                    level: info.level.to_native(),
                    stride: info.stride.to_native(),
                    layer_stride: info.layer_stride.to_native(),
                    offset: info.offset.to_native(),
                };

                self.virtio_gpu
                    .transfer_read(ctx_id, resource_id, transfer, None)
            }
            GpuCommand::CmdSubmit3d(info) => {
                if reader.available_bytes() != 0 {
                    let cmd_size = info.size.to_native() as usize;
                    let mut cmd_buf = vec![0; cmd_size];
                    if reader.read_exact(&mut cmd_buf[..]).is_ok() {
                        self.virtio_gpu
                            .submit_command(info.hdr.ctx_id.to_native(), &mut cmd_buf[..])
                    } else {
                        Err(GpuResponse::ErrInvalidParameter)
                    }
                } else {
                    // Silently accept empty command buffers to allow for
                    // benchmarking.
                    Ok(GpuResponse::OkNoData)
                }
            }
            GpuCommand::ResourceCreateBlob(info) => {
                let resource_id = info.resource_id.to_native();
                let ctx_id = info.hdr.ctx_id.to_native();

                let resource_create_blob = ResourceCreateBlob {
                    blob_mem: info.blob_mem.to_native(),
                    blob_flags: info.blob_flags.to_native(),
                    blob_id: info.blob_id.to_native(),
                    size: info.size.to_native(),
                };

                let entry_count = info.nr_entries.to_native();
                if reader.available_bytes() == 0 && entry_count > 0 {
                    return Err(GpuResponse::ErrUnspec);
                }

                let mut vecs = Vec::with_capacity(entry_count as usize);
                for _ in 0..entry_count {
                    match reader.read_obj::<virtio_gpu_mem_entry>() {
                        Ok(entry) => {
                            let addr = GuestAddress(entry.addr.to_native());
                            let len = entry.length.to_native() as usize;
                            vecs.push((addr, len))
                        }
                        Err(_) => return Err(GpuResponse::ErrUnspec),
                    }
                }

                self.virtio_gpu.resource_create_blob(
                    ctx_id,
                    resource_id,
                    resource_create_blob,
                    vecs,
                    mem,
                )
            }
            GpuCommand::SetScanoutBlob(info) => {
                let scanout_id = info.scanout_id.to_native();
                let resource_id = info.resource_id.to_native();
                let virtio_gpu_format = info.format.to_native();
                let width = info.width.to_native();
                let height = info.width.to_native();
                let mut strides: [u32; 4] = [0; 4];
                let mut offsets: [u32; 4] = [0; 4];

                // As of v4.19, virtio-gpu kms only really uses these formats.  If that changes,
                // the following may have to change too.
                let drm_format = match virtio_gpu_format {
                    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM => DrmFormat::new(b'X', b'R', b'2', b'4'),
                    VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM => DrmFormat::new(b'A', b'R', b'2', b'4'),
                    _ => {
                        error!("unrecognized virtio-gpu format {}", virtio_gpu_format);
                        return Err(GpuResponse::ErrUnspec);
                    }
                };

                for plane_index in 0..PLANE_INFO_MAX_COUNT {
                    offsets[plane_index] = info.offsets[plane_index].to_native();
                    strides[plane_index] = info.strides[plane_index].to_native();
                }

                let scanout = VirtioScanoutBlobData {
                    width,
                    height,
                    drm_format,
                    strides,
                    offsets,
                };

                self.virtio_gpu
                    .set_scanout(scanout_id, resource_id, Some(scanout))
            }
            GpuCommand::ResourceMapBlob(info) => {
                let resource_id = info.resource_id.to_native();
                let offset = info.offset.to_native();
                self.virtio_gpu.resource_map_blob(resource_id, offset)
            }
            GpuCommand::ResourceUnmapBlob(info) => {
                let resource_id = info.resource_id.to_native();
                self.virtio_gpu.resource_unmap_blob(resource_id)
            }
        }
    }

    fn validate_desc(desc: &DescriptorChain) -> bool {
        desc.len as usize >= size_of::<virtio_gpu_ctrl_hdr>() && !desc.is_write_only()
    }

    /// Processes virtio messages on `queue`.
    pub fn process_queue(&mut self, mem: &GuestMemory, queue: &dyn QueueReader) -> bool {
        let mut signal_used = false;
        while let Some(desc) = queue.pop(mem) {
            if Frontend::validate_desc(&desc) {
                match (
                    Reader::new(mem.clone(), desc.clone()),
                    Writer::new(mem.clone(), desc.clone()),
                ) {
                    (Ok(mut reader), Ok(mut writer)) => {
                        if let Some(ret_desc) =
                            self.process_descriptor(mem, desc.index, &mut reader, &mut writer)
                        {
                            queue.add_used(mem, ret_desc.index, ret_desc.len);
                            signal_used = true;
                        }
                    }
                    (_, Err(e)) | (Err(e), _) => {
                        debug!("invalid descriptor: {}", e);
                        queue.add_used(mem, desc.index, 0);
                        signal_used = true;
                    }
                }
            } else {
                let likely_type = mem
                    .read_obj_from_addr(desc.addr)
                    .unwrap_or_else(|_| Le32::from(0));
                debug!(
                    "queue bad descriptor index = {} len = {} write = {} type = {}",
                    desc.index,
                    desc.len,
                    desc.is_write_only(),
                    virtio_gpu_cmd_str(likely_type.to_native())
                );
                queue.add_used(mem, desc.index, 0);
                signal_used = true;
            }
        }

        signal_used
    }

    fn process_descriptor(
        &mut self,
        mem: &GuestMemory,
        desc_index: u16,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> Option<ReturnDescriptor> {
        let mut resp = Err(GpuResponse::ErrUnspec);
        let mut gpu_cmd = None;
        let mut len = 0;
        match GpuCommand::decode(reader) {
            Ok(cmd) => {
                resp = self.process_gpu_command(mem, cmd, reader);
                gpu_cmd = Some(cmd);
            }
            Err(e) => debug!("descriptor decode error: {}", e),
        }

        let mut gpu_response = match resp {
            Ok(gpu_response) => gpu_response,
            Err(gpu_response) => {
                debug!("{:?} -> {:?}", gpu_cmd, gpu_response);
                gpu_response
            }
        };

        if writer.available_bytes() != 0 {
            let mut fence_id = 0;
            let mut ctx_id = 0;
            let mut flags = 0;
            let mut ring_idx = 0;
            if let Some(cmd) = gpu_cmd {
                let ctrl_hdr = cmd.ctrl_hdr();
                if ctrl_hdr.flags.to_native() & VIRTIO_GPU_FLAG_FENCE != 0 {
                    flags = ctrl_hdr.flags.to_native();
                    fence_id = ctrl_hdr.fence_id.to_native();
                    ctx_id = ctrl_hdr.ctx_id.to_native();
                    ring_idx = ctrl_hdr.ring_idx;

                    let fence = RutabagaFence {
                        flags,
                        fence_id,
                        ctx_id,
                        ring_idx,
                    };
                    gpu_response = match self.virtio_gpu.create_fence(fence) {
                        Ok(_) => gpu_response,
                        Err(fence_resp) => {
                            warn!("create_fence {} -> {:?}", fence_id, fence_resp);
                            fence_resp
                        }
                    };
                }
            }

            // Prepare the response now, even if it is going to wait until
            // fence is complete.
            match gpu_response.encode(flags, fence_id, ctx_id, ring_idx, writer) {
                Ok(l) => len = l,
                Err(e) => debug!("ctrl queue response encode error: {}", e),
            }

            if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                let ring = match flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                    0 => VirtioGpuRing::Global,
                    _ => VirtioGpuRing::ContextSpecific { ctx_id, ring_idx },
                };

                // In case the fence is signaled immediately after creation, don't add a return
                // FenceDescriptor.
                let mut fence_state = self.fence_state.lock();
                if fence_id > *fence_state.completed_fences.get(&ring).unwrap_or(&0) {
                    fence_state.descs.push(FenceDescriptor {
                        ring,
                        fence_id,
                        index: desc_index,
                        len,
                    });

                    return None;
                }
            }

            // No fence (or already completed fence), respond now.
        }
        Some(ReturnDescriptor {
            index: desc_index,
            len,
        })
    }

    pub fn return_cursor(&mut self) -> Option<ReturnDescriptor> {
        self.return_cursor_descriptors.pop_front()
    }

    pub fn poll(&self) {
        self.virtio_gpu.poll();
    }
}

struct Worker {
    interrupt: Arc<Interrupt>,
    exit_evt: Event,
    mem: GuestMemory,
    ctrl_queue: SharedQueueReader,
    ctrl_evt: Event,
    cursor_queue: LocalQueueReader,
    cursor_evt: Event,
    resource_bridges: Vec<Tube>,
    kill_evt: Event,
    state: Frontend,
}

impl Worker {
    fn run(&mut self) {
        #[derive(PollToken)]
        enum Token {
            CtrlQueue,
            CursorQueue,
            Display,
            InterruptResample,
            Kill,
            ResourceBridge { index: usize },
            VirtioGpuPoll,
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&self.ctrl_evt, Token::CtrlQueue),
            (&self.cursor_evt, Token::CursorQueue),
            (&*self.state.display().borrow(), Token::Display),
            (&self.kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            if wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .is_err()
            {
                error!("failed creating WaitContext");
                return;
            }
        }

        for (index, bridge) in self.resource_bridges.iter().enumerate() {
            if let Err(e) = wait_ctx.add(bridge, Token::ResourceBridge { index }) {
                error!("failed to add resource bridge to WaitContext: {}", e);
            }
        }

        if let Some(poll_desc) = self.state.virtio_gpu.poll_descriptor() {
            if let Err(e) = wait_ctx.add(&poll_desc, Token::VirtioGpuPoll) {
                error!("failed adding poll eventfd to WaitContext: {}", e);
                return;
            }
        }

        // TODO(davidriley): The entire main loop processing is somewhat racey and incorrect with
        // respect to cursor vs control queue processing.  As both currently and originally
        // written, while the control queue is only processed/read from after the the cursor queue
        // is finished, the entire queue will be processed at that time.  The end effect of this
        // racyiness is that control queue descriptors that are issued after cursors descriptors
        // might be handled first instead of the other way around.  In practice, the cursor queue
        // isn't used so this isn't a huge issue.

        // Declare this outside the loop so we don't keep allocating and freeing the vector.
        let mut process_resource_bridge = Vec::with_capacity(self.resource_bridges.len());
        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };
            let mut signal_used_cursor = false;
            let mut signal_used_ctrl = false;
            let mut ctrl_available = false;

            // Clear the old values and re-initialize with false.
            process_resource_bridge.clear();
            process_resource_bridge.resize(self.resource_bridges.len(), false);

            // This display isn't typically used when the virt-wl device is available and it can
            // lead to hung fds (crbug.com/1027379). Disable if it's hung.
            for event in events.iter().filter(|e| e.is_hungup) {
                if let Token::Display = event.token {
                    error!("default display hang-up detected");
                    let _ = wait_ctx.delete(&*self.state.display().borrow());
                }
            }

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::CtrlQueue => {
                        let _ = self.ctrl_evt.read();
                        // Set flag that control queue is available to be read, but defer reading
                        // until rest of the events are processed.
                        ctrl_available = true;
                    }
                    Token::CursorQueue => {
                        let _ = self.cursor_evt.read();
                        if self.state.process_queue(&self.mem, &self.cursor_queue) {
                            signal_used_cursor = true;
                        }
                    }
                    Token::Display => {
                        let close_requested = self.state.process_display();
                        if close_requested {
                            let _ = self.exit_evt.write(1);
                        }
                    }
                    Token::ResourceBridge { index } => {
                        process_resource_bridge[index] = true;
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::VirtioGpuPoll => {
                        self.state.poll();
                    }
                    Token::Kill => {
                        break 'wait;
                    }
                }
            }

            // All cursor commands go first because they have higher priority.
            while let Some(desc) = self.state.return_cursor() {
                self.cursor_queue.add_used(&self.mem, desc.index, desc.len);
                signal_used_cursor = true;
            }

            if ctrl_available && self.state.process_queue(&self.mem, &self.ctrl_queue) {
                signal_used_ctrl = true;
            }

            // Process the entire control queue before the resource bridge in case a resource is
            // created or destroyed by the control queue. Processing the resource bridge first may
            // lead to a race condition.
            // TODO(davidriley): This is still inherently racey if both the control queue request
            // and the resource bridge request come in at the same time after the control queue is
            // processed above and before the corresponding bridge is processed below.
            for (bridge, &should_process) in
                self.resource_bridges.iter().zip(&process_resource_bridge)
            {
                if should_process {
                    if let Err(e) = self.state.process_resource_bridge(bridge) {
                        error!("Failed to process resource bridge: {:#}", e);
                        error!("Removing that resource bridge from the wait context.");
                        wait_ctx.delete(bridge).unwrap_or_else(|e| {
                            error!("Failed to remove faulty resource bridge: {:#}", e)
                        });
                    }
                }
            }

            if signal_used_ctrl {
                self.ctrl_queue.signal_used(&self.mem);
            }

            if signal_used_cursor {
                self.cursor_queue.signal_used(&self.mem);
            }
        }
    }
}

/// Indicates a backend that should be tried for the gpu to use for display.
///
/// Several instances of this enum are used in an ordered list to give the gpu device many backends
/// to use as fallbacks in case some do not work.
#[derive(Clone)]
pub enum DisplayBackend {
    /// Use the wayland backend with the given socket path if given.
    Wayland(Option<PathBuf>),
    /// Open a connection to the X server at the given display if given.
    X(Option<String>),
    /// Emulate a display without actually displaying it.
    Stub,
}

impl DisplayBackend {
    fn build(&self) -> std::result::Result<GpuDisplay, GpuDisplayError> {
        match self {
            DisplayBackend::Wayland(path) => GpuDisplay::open_wayland(path.as_ref()),
            DisplayBackend::X(display) => GpuDisplay::open_x(display.as_ref()),
            DisplayBackend::Stub => GpuDisplay::open_stub(),
        }
    }
}

pub struct Gpu {
    exit_evt: Event,
    gpu_device_tube: Option<Tube>,
    resource_bridges: Vec<Tube>,
    event_devices: Vec<EventDevice>,
    kill_evt: Option<Event>,
    config_event: bool,
    worker_thread: Option<thread::JoinHandle<()>>,
    display_backends: Vec<DisplayBackend>,
    display_params: Vec<GpuDisplayParameters>,
    rutabaga_builder: Option<RutabagaBuilder>,
    pci_bar: Option<Alloc>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    external_blob: bool,
    rutabaga_component: RutabagaComponentType,
    base_features: u64,
    udmabuf: bool,
    render_server_fd: Option<SafeDescriptor>,
}

impl Gpu {
    pub fn new(
        exit_evt: Event,
        gpu_device_tube: Option<Tube>,
        resource_bridges: Vec<Tube>,
        display_backends: Vec<DisplayBackend>,
        gpu_parameters: &GpuParameters,
        render_server_fd: Option<SafeDescriptor>,
        event_devices: Vec<EventDevice>,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        external_blob: bool,
        base_features: u64,
        channels: BTreeMap<String, PathBuf>,
    ) -> Gpu {
        let virglrenderer_flags = VirglRendererFlags::new()
            .use_egl(gpu_parameters.renderer_use_egl)
            .use_gles(gpu_parameters.renderer_use_gles)
            .use_glx(gpu_parameters.renderer_use_glx)
            .use_surfaceless(gpu_parameters.renderer_use_surfaceless)
            .use_external_blob(external_blob)
            .use_venus(gpu_parameters.use_vulkan)
            .use_render_server(render_server_fd.is_some())
            .use_thread_sync(true)
            .use_async_fence_cb(true);
        let gfxstream_flags = GfxstreamFlags::new()
            .use_egl(gpu_parameters.renderer_use_egl)
            .use_gles(gpu_parameters.renderer_use_gles)
            .use_glx(gpu_parameters.renderer_use_glx)
            .use_surfaceless(gpu_parameters.renderer_use_surfaceless)
            .use_guest_angle(gpu_parameters.gfxstream_use_guest_angle)
            .use_syncfd(gpu_parameters.gfxstream_use_syncfd)
            .use_vulkan(gpu_parameters.use_vulkan)
            .use_async_fence_cb(true);

        let mut rutabaga_channels: Vec<RutabagaChannel> = Vec::new();
        for (channel_name, path) in &channels {
            match &channel_name[..] {
                "" => rutabaga_channels.push(RutabagaChannel {
                    base_channel: path.clone(),
                    channel_type: RUTABAGA_CHANNEL_TYPE_WAYLAND,
                }),
                "mojo" => rutabaga_channels.push(RutabagaChannel {
                    base_channel: path.clone(),
                    channel_type: RUTABAGA_CHANNEL_TYPE_CAMERA,
                }),
                _ => error!("unknown rutabaga channel"),
            }
        }

        let rutabaga_channels_opt = Some(rutabaga_channels);
        let component = match gpu_parameters.mode {
            GpuMode::Mode2D => RutabagaComponentType::Rutabaga2D,
            GpuMode::ModeVirglRenderer => RutabagaComponentType::VirglRenderer,
            GpuMode::ModeGfxstream => RutabagaComponentType::Gfxstream,
        };

        let mut display_width = DEFAULT_DISPLAY_WIDTH;
        let mut display_height = DEFAULT_DISPLAY_HEIGHT;
        if !gpu_parameters.displays.is_empty() {
            display_width = gpu_parameters.displays[0].width;
            display_height = gpu_parameters.displays[0].height;
        }

        let rutabaga_builder = RutabagaBuilder::new(component)
            .set_display_width(display_width)
            .set_display_height(display_height)
            .set_virglrenderer_flags(virglrenderer_flags)
            .set_gfxstream_flags(gfxstream_flags)
            .set_rutabaga_channels(rutabaga_channels_opt);

        Gpu {
            exit_evt,
            gpu_device_tube,
            resource_bridges,
            event_devices,
            config_event: false,
            kill_evt: None,
            worker_thread: None,
            display_backends,
            display_params: gpu_parameters.displays.clone(),
            rutabaga_builder: Some(rutabaga_builder),
            pci_bar: None,
            map_request,
            external_blob,
            rutabaga_component: component,
            base_features,
            udmabuf: gpu_parameters.udmabuf,
            render_server_fd,
        }
    }

    /// Initializes the internal device state so that it can begin processing virtqueues.
    pub fn initialize_frontend(
        &mut self,
        fence_state: Arc<Mutex<FenceState>>,
        fence_handler: RutabagaFenceHandler,
    ) -> Option<Frontend> {
        let tube = self.gpu_device_tube.take()?;
        let pci_bar = self.pci_bar.take()?;
        let rutabaga_builder = self.rutabaga_builder.take()?;
        let render_server_fd = self.render_server_fd.take();
        let event_devices = self.event_devices.split_off(0);

        build(
            &self.display_backends,
            self.display_params.clone(),
            rutabaga_builder,
            event_devices,
            tube,
            pci_bar,
            self.map_request.clone(),
            self.external_blob,
            self.udmabuf,
            fence_handler,
            render_server_fd,
        )
        .map(|vgpu| Frontend::new(vgpu, fence_state))
    }

    /// Returns the device tube to the main process.
    pub fn device_tube(&self) -> Option<&Tube> {
        self.gpu_device_tube.as_ref()
    }

    /// Sets the device tube to the main process.
    pub fn set_device_tube(&mut self, tube: Tube) {
        self.gpu_device_tube = Some(tube);
    }

    fn get_config(&self) -> virtio_gpu_config {
        let mut events_read = 0;
        if self.config_event {
            events_read |= VIRTIO_GPU_EVENT_DISPLAY;
        }

        let num_capsets = match self.rutabaga_component {
            RutabagaComponentType::Rutabaga2D => 0,
            _ => {
                let mut num_capsets = 0;

                // Cross-domain (like virtio_wl with llvmpipe) is always available.
                num_capsets += 1;

                // Three capsets for virgl_renderer
                #[cfg(feature = "virgl_renderer")]
                {
                    num_capsets += 3;
                }

                // One capset for gfxstream
                #[cfg(feature = "gfxstream")]
                {
                    num_capsets += 1;
                }

                num_capsets
            }
        };

        virtio_gpu_config {
            events_read: Le32::from(events_read),
            events_clear: Le32::from(0),
            num_scanouts: Le32::from(self.display_params.len() as u32),
            num_capsets: Le32::from(num_capsets),
        }
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Gpu {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();
        // TODO(davidriley): Remove once virgl has another path to include
        // debugging logs.
        if cfg!(debug_assertions) {
            keep_rds.push(libc::STDOUT_FILENO);
            keep_rds.push(libc::STDERR_FILENO);
        }

        if let Some(ref gpu_device_tube) = self.gpu_device_tube {
            keep_rds.push(gpu_device_tube.as_raw_descriptor());
        }

        if let Some(ref render_server_fd) = self.render_server_fd {
            keep_rds.push(render_server_fd.as_raw_descriptor());
        }

        keep_rds.push(self.exit_evt.as_raw_descriptor());
        for bridge in &self.resource_bridges {
            keep_rds.push(bridge.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> u32 {
        TYPE_GPU
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        let rutabaga_features = match self.rutabaga_component {
            RutabagaComponentType::Rutabaga2D => 0,
            _ => {
                let mut features_3d = 0;

                features_3d |= 1 << VIRTIO_GPU_F_VIRGL
                    | 1 << VIRTIO_GPU_F_RESOURCE_UUID
                    | 1 << VIRTIO_GPU_F_RESOURCE_BLOB
                    | 1 << VIRTIO_GPU_F_CONTEXT_INIT
                    | 1 << VIRTIO_GPU_F_RESOURCE_SYNC;

                if self.udmabuf {
                    features_3d |= 1 << VIRTIO_GPU_F_CREATE_GUEST_HANDLE;
                }

                features_3d
            }
        };

        self.base_features | rutabaga_features
    }

    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_slice(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut cfg = self.get_config();
        copy_config(cfg.as_mut_slice(), offset, data, 0);
        if (cfg.events_clear.to_native() & VIRTIO_GPU_EVENT_DISPLAY) != 0 {
            self.config_event = false;
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            return;
        }

        let exit_evt = match self.exit_evt.try_clone() {
            Ok(e) => e,
            Err(e) => {
                error!("error cloning exit event: {}", e);
                return;
            }
        };

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("error creating kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let resource_bridges = mem::take(&mut self.resource_bridges);

        let irq = Arc::new(interrupt);
        let ctrl_queue = SharedQueueReader::new(queues.remove(0), &irq);
        let ctrl_evt = queue_evts.remove(0);
        let cursor_queue = LocalQueueReader::new(queues.remove(0), &irq);
        let cursor_evt = queue_evts.remove(0);
        let display_backends = self.display_backends.clone();
        let display_params = self.display_params.clone();
        let event_devices = self.event_devices.split_off(0);
        let map_request = Arc::clone(&self.map_request);
        let external_blob = self.external_blob;
        let udmabuf = self.udmabuf;
        let fence_state = Arc::new(Mutex::new(Default::default()));
        let render_server_fd = self.render_server_fd.take();
        if let (Some(gpu_device_tube), Some(pci_bar), Some(rutabaga_builder)) = (
            self.gpu_device_tube.take(),
            self.pci_bar.take(),
            self.rutabaga_builder.take(),
        ) {
            let worker_result =
                thread::Builder::new()
                    .name("virtio_gpu".to_string())
                    .spawn(move || {
                        let fence_handler = create_fence_handler(
                            mem.clone(),
                            ctrl_queue.clone(),
                            fence_state.clone(),
                        );

                        let virtio_gpu = match build(
                            &display_backends,
                            display_params,
                            rutabaga_builder,
                            event_devices,
                            gpu_device_tube,
                            pci_bar,
                            map_request,
                            external_blob,
                            udmabuf,
                            fence_handler,
                            render_server_fd,
                        ) {
                            Some(backend) => backend,
                            None => return,
                        };

                        Worker {
                            interrupt: irq,
                            exit_evt,
                            mem,
                            ctrl_queue: ctrl_queue.clone(),
                            ctrl_evt,
                            cursor_queue,
                            cursor_evt,
                            resource_bridges,
                            kill_evt,
                            state: Frontend::new(virtio_gpu, fence_state),
                        }
                        .run()
                    });

            match worker_result {
                Err(e) => {
                    error!("failed to spawn virtio_gpu worker: {}", e);
                    return;
                }
                Ok(join_handle) => {
                    self.worker_thread = Some(join_handle);
                }
            }
        }
    }

    // Require 1 BAR for mapping 3D buffers
    fn get_device_bars(&mut self, address: PciAddress) -> Vec<PciBarConfiguration> {
        self.pci_bar = Some(Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: GPU_BAR_NUM,
        });
        vec![PciBarConfiguration::new(
            GPU_BAR_NUM as usize,
            GPU_BAR_SIZE,
            PciBarRegionType::Memory64BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )]
    }

    fn get_device_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![Box::new(VirtioPciShmCap::new(
            PciCapabilityType::SharedMemoryConfig,
            GPU_BAR_NUM,
            GPU_BAR_OFFSET,
            GPU_BAR_SIZE,
            VIRTIO_GPU_SHM_ID_HOST_VISIBLE,
        ))]
    }
}
