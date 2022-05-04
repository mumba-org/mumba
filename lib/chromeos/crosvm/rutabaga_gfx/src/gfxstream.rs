// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! gfxstream: Handles 3D virtio-gpu hypercalls using gfxstream.
//!
//! External code found at <https://android.googlesource.com/device/generic/vulkan-cereal/>.

#![cfg(feature = "gfxstream")]

use std::convert::TryInto;
use std::mem::{size_of, transmute};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr::{null, null_mut};
use std::sync::Arc;

use base::{
    ExternalMapping, ExternalMappingError, ExternalMappingResult, FromRawDescriptor,
    IntoRawDescriptor, SafeDescriptor,
};

use crate::generated::virgl_renderer_bindings::{
    iovec, virgl_box, virgl_renderer_resource_create_args,
};

use crate::renderer_utils::*;
use crate::rutabaga_core::{RutabagaComponent, RutabagaContext, RutabagaResource};
use crate::rutabaga_utils::*;

use data_model::VolatileSlice;

#[repr(C)]
pub struct VirglRendererGlCtxParam {
    pub version: c_int,
    pub shared: bool,
    pub major_ver: c_int,
    pub minor_ver: c_int,
}

// In gfxstream, only write_fence is used (for synchronization of commands delivered)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VirglRendererCallbacks {
    pub version: c_int,
    pub write_fence: unsafe extern "C" fn(cookie: *mut c_void, fence: u32),
    pub create_gl_context: Option<
        unsafe extern "C" fn(
            cookie: *mut c_void,
            scanout_idx: c_int,
            param: *mut VirglRendererGlCtxParam,
        ) -> *mut c_void,
    >,
    pub destroy_gl_context: Option<unsafe extern "C" fn(cookie: *mut c_void, ctx: *mut c_void)>,
    pub make_current: Option<
        unsafe extern "C" fn(cookie: *mut c_void, scanout_idx: c_int, ctx: *mut c_void) -> c_int,
    >,

    pub get_drm_fd: Option<unsafe extern "C" fn(cookie: *mut c_void) -> c_int>,
    pub write_context_fence:
        unsafe extern "C" fn(cookie: *mut c_void, fence_id: u64, ctx_id: u32, ring_idx: u8),
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct stream_renderer_handle {
    pub os_handle: i64,
    pub handle_type: u32,
}

#[allow(non_camel_case_types)]
type stream_renderer_create_blob = ResourceCreateBlob;

#[link(name = "gfxstream_backend")]
extern "C" {

    // Function to globally init gfxstream backend's internal state, taking display/renderer
    // parameters.
    fn gfxstream_backend_init(
        display_width: u32,
        display_height: u32,
        display_type: u32,
        renderer_cookie: *mut c_void,
        renderer_flags: i32,
        renderer_callbacks: *mut VirglRendererCallbacks,
        gfxstream_callbacks: *mut c_void,
    );

    // virtio-gpu-3d ioctl functions (begin)

    // In gfxstream, the resource create/transfer ioctls correspond to creating buffers for API
    // forwarding and the notification of new API calls forwarded by the guest, unless they
    // correspond to minigbm resource targets (PIPE_TEXTURE_2D), in which case they create globally
    // visible shared GL textures to support gralloc.
    fn pipe_virgl_renderer_resource_create(
        args: *mut virgl_renderer_resource_create_args,
        iov: *mut iovec,
        num_iovs: u32,
    ) -> c_int;

    fn pipe_virgl_renderer_resource_unref(res_handle: u32);
    fn pipe_virgl_renderer_context_create(handle: u32, nlen: u32, name: *const c_char) -> c_int;
    fn pipe_virgl_renderer_context_destroy(handle: u32);
    fn pipe_virgl_renderer_transfer_read_iov(
        handle: u32,
        ctx_id: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        box_: *mut virgl_box,
        offset: u64,
        iov: *mut iovec,
        iovec_cnt: c_int,
    ) -> c_int;
    fn pipe_virgl_renderer_transfer_write_iov(
        handle: u32,
        ctx_id: u32,
        level: c_int,
        stride: u32,
        layer_stride: u32,
        box_: *mut virgl_box,
        offset: u64,
        iovec: *mut iovec,
        iovec_cnt: c_uint,
    ) -> c_int;
    fn pipe_virgl_renderer_submit_cmd(
        commands: *mut c_void,
        ctx_id: i32,
        dword_count: i32,
    ) -> c_int;
    fn pipe_virgl_renderer_resource_attach_iov(
        res_handle: c_int,
        iov: *mut iovec,
        num_iovs: c_int,
    ) -> c_int;
    fn pipe_virgl_renderer_resource_detach_iov(
        res_handle: c_int,
        iov: *mut *mut iovec,
        num_iovs: *mut c_int,
    );
    fn pipe_virgl_renderer_create_fence(client_fence_id: c_int, ctx_id: u32) -> c_int;
    fn pipe_virgl_renderer_ctx_attach_resource(ctx_id: c_int, res_handle: c_int);
    fn pipe_virgl_renderer_ctx_detach_resource(ctx_id: c_int, res_handle: c_int);

    fn stream_renderer_create_blob(
        ctx_id: u32,
        res_handle: u32,
        create_blob: *const stream_renderer_create_blob,
        iovecs: *const iovec,
        num_iovs: u32,
        handle: *const stream_renderer_handle,
    ) -> c_int;

    fn stream_renderer_export_blob(res_handle: u32, handle: *mut stream_renderer_handle) -> c_int;
    fn stream_renderer_resource_map(
        res_handle: u32,
        map: *mut *mut c_void,
        out_size: *mut u64,
    ) -> c_int;
    fn stream_renderer_resource_unmap(res_handle: u32) -> c_int;
    fn stream_renderer_resource_map_info(res_handle: u32, map_info: *mut u32) -> c_int;
    fn stream_renderer_context_create_fence(fence_id: u64, ctx_id: u32, ring_idx: u8) -> c_int;
}

/// The virtio-gpu backend state tracker which supports accelerated rendering.
pub struct Gfxstream;

struct GfxstreamContext {
    ctx_id: u32,
}

impl RutabagaContext for GfxstreamContext {
    fn submit_cmd(&mut self, commands: &mut [u8]) -> RutabagaResult<()> {
        if commands.len() % size_of::<u32>() != 0 {
            return Err(RutabagaError::InvalidCommandSize(commands.len()));
        }
        let dword_count = (commands.len() / size_of::<u32>()) as i32;
        // Safe because the context and buffer are valid and virglrenderer will have been
        // initialized if there are Context instances.
        let ret = unsafe {
            pipe_virgl_renderer_submit_cmd(
                commands.as_mut_ptr() as *mut c_void,
                self.ctx_id as i32,
                dword_count,
            )
        };
        ret_to_res(ret)
    }

    fn attach(&mut self, resource: &mut RutabagaResource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            pipe_virgl_renderer_ctx_attach_resource(
                self.ctx_id as i32,
                resource.resource_id as i32,
            );
        }
    }

    fn detach(&mut self, resource: &RutabagaResource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            pipe_virgl_renderer_ctx_detach_resource(
                self.ctx_id as i32,
                resource.resource_id as i32,
            );
        }
    }

    fn component_type(&self) -> RutabagaComponentType {
        RutabagaComponentType::Gfxstream
    }

    fn context_create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        // Safe becase only integers are given to gfxstream, not memory.
        let ret = unsafe {
            stream_renderer_context_create_fence(fence.fence_id, fence.ctx_id, fence.ring_idx)
        };

        ret_to_res(ret)
    }
}

impl Drop for GfxstreamContext {
    fn drop(&mut self) {
        // The context is safe to destroy because nothing else can be referencing it.
        unsafe {
            pipe_virgl_renderer_context_destroy(self.ctx_id);
        }
    }
}

const GFXSTREAM_RENDERER_CALLBACKS: &VirglRendererCallbacks = &VirglRendererCallbacks {
    version: 3,
    write_fence,
    create_gl_context: None,
    destroy_gl_context: None,
    make_current: None,
    get_drm_fd: None,
    write_context_fence,
};

fn map_func(resource_id: u32) -> ExternalMappingResult<(u64, usize)> {
    let mut map: *mut c_void = null_mut();
    let map_ptr: *mut *mut c_void = &mut map;
    let mut size: u64 = 0;

    // Safe because the Stream renderer wraps and validates use of vkMapMemory.
    let ret = unsafe { stream_renderer_resource_map(resource_id, map_ptr, &mut size) };
    if ret != 0 {
        return Err(ExternalMappingError::LibraryError(ret));
    }
    Ok((map as u64, size as usize))
}

fn unmap_func(resource_id: u32) {
    unsafe { stream_renderer_resource_unmap(resource_id) };
}

impl Gfxstream {
    pub fn init(
        display_width: u32,
        display_height: u32,
        gfxstream_flags: GfxstreamFlags,
        fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        let cookie: *mut VirglCookie = Box::into_raw(Box::new(VirglCookie {
            render_server_fd: None,
            fence_handler: Some(fence_handler),
        }));

        unsafe {
            gfxstream_backend_init(
                display_width,
                display_height,
                1, /* default to shmem display */
                cookie as *mut c_void,
                gfxstream_flags.into(),
                transmute(GFXSTREAM_RENDERER_CALLBACKS),
                null_mut(),
            );
        }

        Ok(Box::new(Gfxstream))
    }

    fn map_info(&self, resource_id: u32) -> RutabagaResult<u32> {
        let mut map_info = 0;
        let ret = unsafe { stream_renderer_resource_map_info(resource_id, &mut map_info) };
        ret_to_res(ret)?;

        Ok(map_info)
    }

    fn export_blob(&self, resource_id: u32) -> RutabagaResult<Arc<RutabagaHandle>> {
        let mut stream_handle: stream_renderer_handle = Default::default();
        let ret = unsafe { stream_renderer_export_blob(resource_id as u32, &mut stream_handle) };
        ret_to_res(ret)?;

        // Safe because the handle was just returned by a successful gfxstream call so it must be
        // valid and owned by us.
        let raw_descriptor = stream_handle.os_handle.try_into()?;
        let handle = unsafe { SafeDescriptor::from_raw_descriptor(raw_descriptor) };

        Ok(Arc::new(RutabagaHandle {
            os_handle: handle,
            handle_type: stream_handle.handle_type,
        }))
    }
}

impl RutabagaComponent for Gfxstream {
    fn get_capset_info(&self, _capset_id: u32) -> (u32, u32) {
        (1, 0)
    }

    fn get_capset(&self, _capset_id: u32, _version: u32) -> Vec<u8> {
        Vec::new()
    }

    fn create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        let ret = unsafe { pipe_virgl_renderer_create_fence(fence.fence_id as i32, fence.ctx_id) };

        ret_to_res(ret)
    }

    fn create_3d(
        &self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<RutabagaResource> {
        let mut args = virgl_renderer_resource_create_args {
            handle: resource_id,
            target: resource_create_3d.target,
            format: resource_create_3d.format,
            bind: resource_create_3d.bind,
            width: resource_create_3d.width,
            height: resource_create_3d.height,
            depth: resource_create_3d.depth,
            array_size: resource_create_3d.array_size,
            last_level: resource_create_3d.last_level,
            nr_samples: resource_create_3d.nr_samples,
            flags: resource_create_3d.flags,
        };

        // Safe because virglrenderer is initialized by now, and the return value is checked before
        // returning a new resource. The backing buffers are not supplied with this call.
        let ret = unsafe { pipe_virgl_renderer_resource_create(&mut args, null_mut(), 0) };
        ret_to_res(ret)?;

        Ok(RutabagaResource {
            resource_id,
            handle: None,
            blob: false,
            blob_mem: 0,
            blob_flags: 0,
            map_info: None,
            info_2d: None,
            info_3d: None,
            vulkan_info: None,
            backing_iovecs: None,
        })
    }

    fn attach_backing(
        &self,
        resource_id: u32,
        vecs: &mut Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        let ret = unsafe {
            pipe_virgl_renderer_resource_attach_iov(
                resource_id as i32,
                vecs.as_mut_ptr() as *mut iovec,
                vecs.len() as i32,
            )
        };
        ret_to_res(ret)
    }

    fn detach_backing(&self, resource_id: u32) {
        unsafe {
            pipe_virgl_renderer_resource_detach_iov(
                resource_id as i32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }
    }

    fn unref_resource(&self, resource_id: u32) {
        // The resource is safe to unreference destroy because no user of these bindings can still
        // be holding a reference.
        unsafe {
            pipe_virgl_renderer_resource_unref(resource_id);
        }
    }

    fn transfer_write(
        &self,
        ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut transfer_box = VirglBox {
            x: transfer.x,
            y: transfer.y,
            z: transfer.z,
            w: transfer.w,
            h: transfer.h,
            d: transfer.d,
        };

        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            pipe_virgl_renderer_transfer_write_iov(
                resource.resource_id,
                ctx_id,
                transfer.level as i32,
                transfer.stride,
                transfer.layer_stride,
                &mut transfer_box as *mut VirglBox as *mut virgl_box,
                transfer.offset,
                null_mut(),
                0,
            )
        };
        ret_to_res(ret)
    }

    fn transfer_read(
        &self,
        ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut transfer_box = VirglBox {
            x: transfer.x,
            y: transfer.y,
            z: transfer.z,
            w: transfer.w,
            h: transfer.h,
            d: transfer.d,
        };

        let mut iov = RutabagaIovec {
            base: null_mut(),
            len: 0,
        };

        let (iovecs, num_iovecs) = match buf {
            Some(buf) => {
                iov.base = buf.as_ptr() as *mut c_void;
                iov.len = buf.size() as usize;
                (&mut iov as *mut RutabagaIovec as *mut iovec, 1)
            }
            None => (null_mut(), 0),
        };

        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            pipe_virgl_renderer_transfer_read_iov(
                resource.resource_id,
                ctx_id,
                transfer.level,
                transfer.stride,
                transfer.layer_stride,
                &mut transfer_box as *mut VirglBox as *mut virgl_box,
                transfer.offset,
                iovecs,
                num_iovecs,
            )
        };
        ret_to_res(ret)
    }

    fn create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        mut iovec_opt: Option<Vec<RutabagaIovec>>,
        handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        let mut iovec_ptr = null_mut();
        let mut num_iovecs = 0;
        if let Some(ref mut iovecs) = iovec_opt {
            iovec_ptr = iovecs.as_mut_ptr();
            num_iovecs = iovecs.len() as u32;
        }

        let mut handle_ptr = null();
        let mut stream_handle: stream_renderer_handle = Default::default();
        if let Some(handle) = handle_opt {
            stream_handle.handle_type = handle.handle_type;
            stream_handle.os_handle = handle.os_handle.into_raw_descriptor() as i64;
            handle_ptr = &stream_handle;
        }

        let ret = unsafe {
            stream_renderer_create_blob(
                ctx_id,
                resource_id,
                &resource_create_blob as *const stream_renderer_create_blob,
                iovec_ptr as *const iovec,
                num_iovecs,
                handle_ptr as *const stream_renderer_handle,
            )
        };

        ret_to_res(ret)?;

        Ok(RutabagaResource {
            resource_id,
            handle: self.export_blob(resource_id).ok(),
            blob: true,
            blob_mem: resource_create_blob.blob_mem,
            blob_flags: resource_create_blob.blob_flags,
            map_info: self.map_info(resource_id).ok(),
            info_2d: None,
            info_3d: None,
            vulkan_info: None,
            backing_iovecs: iovec_opt,
        })
    }

    fn map(&self, resource_id: u32) -> RutabagaResult<ExternalMapping> {
        let map_result = unsafe { ExternalMapping::new(resource_id, map_func, unmap_func) };
        match map_result {
            Ok(mapping) => Ok(mapping),
            Err(e) => Err(RutabagaError::MappingFailed(e)),
        }
    }

    fn create_context(
        &self,
        ctx_id: u32,
        _context_init: u32,
        _fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        const CONTEXT_NAME: &[u8] = b"gpu_renderer";
        // Safe because virglrenderer is initialized by now and the context name is statically
        // allocated. The return value is checked before returning a new context.
        let ret = unsafe {
            pipe_virgl_renderer_context_create(
                ctx_id,
                CONTEXT_NAME.len() as u32,
                CONTEXT_NAME.as_ptr() as *const c_char,
            )
        };
        ret_to_res(ret)?;
        Ok(Box::new(GfxstreamContext { ctx_id }))
    }
}
