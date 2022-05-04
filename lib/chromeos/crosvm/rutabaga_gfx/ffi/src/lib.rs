// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

///! C-bindings for the rutabaga_gfx crate
extern crate rutabaga_gfx;

use std::convert::TryInto;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::slice::{from_raw_parts, from_raw_parts_mut};

use base::{error, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor};
use data_model::VolatileSlice;

use libc::{iovec, EINVAL, ESRCH};

use rutabaga_gfx::*;

const NO_ERROR: i32 = 0;

fn return_result<T>(result: RutabagaResult<T>) -> i32 {
    if let Err(e) = result {
        error!("Received an error {}", e);
        -EINVAL
    } else {
        NO_ERROR
    }
}

macro_rules! return_on_error {
    ($result:expr) => {
        match $result {
            Ok(t) => t,
            Err(e) => {
                error!("Received an error {}", e);
                return -EINVAL;
            }
        }
    };
}

const RUTABAGA_COMPONENT_2D: u32 = 1;
const RUTABAGA_COMPONENT_VIRGL_RENDERER: u32 = 2;
const RUTABAGA_COMPONENT_GFXSTREAM: u32 = 3;
const RUTABAGA_COMPONENT_CROSS_DOMAIN: u32 = 4;

#[allow(non_camel_case_types)]
type rutabaga = Rutabaga;

#[allow(non_camel_case_types)]
type rutabaga_create_blob = ResourceCreateBlob;

#[allow(non_camel_case_types)]
type rutabaga_create_3d = ResourceCreate3D;

#[allow(non_camel_case_types)]
type rutabaga_transfer = Transfer3D;

#[allow(non_camel_case_types)]
type rutabaga_fence = RutabagaFence;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rutabaga_iovecs {
    pub iovecs: *mut iovec,
    pub num_iovecs: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rutabaga_handle {
    pub os_handle: i32,
    pub handle_type: u32,
}

#[repr(C)]
pub struct rutabaga_channel {
    pub channel_name: *const c_char,
    pub channel_type: u32,
}

#[repr(C)]
pub struct rutabaga_channels {
    pub channels: *const rutabaga_channel,
    pub num_channels: usize,
}

#[allow(non_camel_case_types)]
pub type write_fence_cb = extern "C" fn(user_data: u64, fence_data: rutabaga_fence);

#[repr(C)]
pub struct rutabaga_builder<'a> {
    pub user_data: u64,
    pub default_component: u32,
    pub fence_cb: write_fence_cb,
    pub channels: Option<&'a rutabaga_channels>,
}

fn create_ffi_fence_handler(user_data: u64, fence_cb: write_fence_cb) -> RutabagaFenceHandler {
    RutabagaFenceClosure::new(move |completed_fence| fence_cb(user_data, completed_fence))
}

/// # Safety
/// - If `(*builder).channels` is not null, the caller must ensure `(*channels).channels` points to
///   a valid array of `struct rutabaga_channel` of size `(*channels).num_channels`.
/// - The `channel_name` field of `struct rutabaga_channel` must be a null-terminated C-string.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_init(builder: &rutabaga_builder, ptr: &mut *mut rutabaga) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let fence_handler = create_ffi_fence_handler((*builder).user_data, (*builder).fence_cb);

        let component = match (*builder).default_component {
            RUTABAGA_COMPONENT_2D => RutabagaComponentType::Rutabaga2D,
            RUTABAGA_COMPONENT_VIRGL_RENDERER => RutabagaComponentType::VirglRenderer,
            RUTABAGA_COMPONENT_GFXSTREAM => RutabagaComponentType::Gfxstream,
            RUTABAGA_COMPONENT_CROSS_DOMAIN => RutabagaComponentType::CrossDomain,
            _ => {
                error!("unknown component type");
                return -EINVAL;
            }
        };

        let virglrenderer_flags = VirglRendererFlags::new()
            .use_egl(true)
            .use_surfaceless(true)
            .use_external_blob(true);

        let gfxstream_flags = GfxstreamFlags::new()
            .use_egl(true)
            .use_surfaceless(true)
            .use_guest_angle(true)
            .use_syncfd(true)
            .use_vulkan(true);

        let mut rutabaga_channels_opt = None;
        if let Some(channels) = (*builder).channels {
            let mut rutabaga_channels: Vec<RutabagaChannel> = Vec::new();
            let channels_slice = from_raw_parts(channels.channels, channels.num_channels);

            for channel in channels_slice {
                let c_str_slice = CStr::from_ptr(channel.channel_name);
                let result = c_str_slice.to_str();
                let str_slice = return_on_error!(result);
                let string = str_slice.to_owned();
                let path = PathBuf::from(&string);

                rutabaga_channels.push(RutabagaChannel {
                    base_channel: path,
                    channel_type: channel.channel_type,
                });
            }

            rutabaga_channels_opt = Some(rutabaga_channels);
        }
        let result = RutabagaBuilder::new(component)
            .set_virglrenderer_flags(virglrenderer_flags)
            .set_gfxstream_flags(gfxstream_flags)
            .set_rutabaga_channels(rutabaga_channels_opt)
            .build(fence_handler, None);

        let rtbg = return_on_error!(result);
        *ptr = Box::into_raw(Box::new(rtbg)) as _;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - `ptr` must have been created by `rutabaga_init`.
#[no_mangle]
pub extern "C" fn rutabaga_finish(ptr: &mut *mut rutabaga) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        unsafe { Box::from_raw(*ptr) };
        *ptr = null_mut();
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_get_num_capsets() -> u32 {
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

#[no_mangle]
pub extern "C" fn rutabaga_get_capset_info(
    ptr: &mut rutabaga,
    capset_index: u32,
    capset_id: &mut u32,
    capset_version: &mut u32,
    capset_size: &mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.get_capset_info(capset_index);
        let info = return_on_error!(result);
        *capset_id = info.0;
        *capset_version = info.1;
        *capset_size = info.2;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - `capset` must point an array of bytes of size `capset_size`.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_get_capset(
    ptr: &mut rutabaga,
    capset_id: u32,
    version: u32,
    capset: *mut u8,
    capset_size: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let size: usize = capset_size.try_into().map_err(|_e| -EINVAL).unwrap();
        let result = ptr.get_capset(capset_id, version);
        let vec = return_on_error!(result);
        copy_nonoverlapping(vec.as_ptr(), capset, size);
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_create(
    ptr: &mut rutabaga,
    ctx_id: u32,
    context_init: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.create_context(ctx_id, context_init);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_destroy(ptr: &mut rutabaga, ctx_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.destroy_context(ctx_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_attach_resource(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.context_attach_resource(ctx_id, resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_detach_resource(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.context_detach_resource(ctx_id, resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_create_3d(
    ptr: &mut rutabaga,
    resource_id: u32,
    create_3d: &rutabaga_create_3d,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.resource_create_3d(resource_id, *create_3d);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
///   iovecs of size `(*iovecs).num_iovecs`.
/// - Each iovec must point to valid memory starting at `iov_base` with length `iov_len`.
/// - Each iovec must valid until the resource's backing is explictly detached or the resource is
///   is unreferenced.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_resource_attach_backing(
    ptr: &mut rutabaga,
    resource_id: u32,
    iovecs: &rutabaga_iovecs,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = from_raw_parts((*iovecs).iovecs, (*iovecs).num_iovecs);
        let vecs = slice
            .iter()
            .map(|iov| RutabagaIovec {
                base: iov.iov_base,
                len: iov.iov_len,
            })
            .collect();

        let result = ptr.attach_backing(resource_id, vecs);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_detach_backing(ptr: &mut rutabaga, resource_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.detach_backing(resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
///   iovecs of size `(*iovecs).num_iovecs`.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_resource_transfer_read(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
    transfer: &rutabaga_transfer,
    buf: Option<&iovec>,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let mut slice_opt = None;
        if let Some(iovec) = buf {
            slice_opt = Some(VolatileSlice::from_raw_parts(
                iovec.iov_base as *mut u8,
                iovec.iov_len,
            ));
        }

        let result = ptr.transfer_read(ctx_id, resource_id, *transfer, slice_opt);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_transfer_write(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
    transfer: &rutabaga_transfer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.transfer_write(ctx_id, resource_id, *transfer);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
///   iovecs of size `(*iovecs).num_iovecs`.
/// - If `handle` is not null, the caller must ensure it is a valid OS-descriptor.  Ownership is
///   transfered to rutabaga.
/// - Each iovec must valid until the resource's backing is explictly detached or the resource is
///   is unreferenced.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_resource_create_blob(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
    create_blob: &rutabaga_create_blob,
    iovecs: Option<&rutabaga_iovecs>,
    handle: Option<&rutabaga_handle>,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let mut iovecs_opt: Option<Vec<RutabagaIovec>> = None;
        if let Some(iovs) = iovecs {
            let slice = from_raw_parts((*iovs).iovecs, (*iovs).num_iovecs);
            let vecs = slice
                .iter()
                .map(|iov| RutabagaIovec {
                    base: iov.iov_base,
                    len: iov.iov_len,
                })
                .collect();
            iovecs_opt = Some(vecs);
        }

        let mut handle_opt: Option<RutabagaHandle> = None;
        if let Some(hnd) = handle {
            handle_opt = Some(RutabagaHandle {
                os_handle: SafeDescriptor::from_raw_descriptor((*hnd).os_handle),
                handle_type: (*hnd).handle_type,
            });
        }

        let result =
            ptr.resource_create_blob(ctx_id, resource_id, *create_blob, iovecs_opt, handle_opt);

        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_unref(ptr: &mut rutabaga, resource_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.unref_resource(resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// Caller owns raw descriptor on success and is responsible for closing it.
#[no_mangle]
pub extern "C" fn rutabaga_resource_export_blob(
    ptr: &mut rutabaga,
    resource_id: u32,
    handle: &mut rutabaga_handle,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.export_blob(resource_id);
        let hnd = return_on_error!(result);

        (*handle).handle_type = hnd.handle_type;
        (*handle).os_handle = hnd.os_handle.into_raw_descriptor();
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_map_info(
    ptr: &mut rutabaga,
    resource_id: u32,
    map_info: &mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.map_info(resource_id);
        *map_info = return_on_error!(result);
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - `commands` must point to a contiguous memory region of `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_submit_command(
    ptr: &mut rutabaga,
    ctx_id: u32,
    commands: *mut u8,
    size: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let cmd_slice = from_raw_parts_mut(commands, size);
        let result = ptr.submit_command(ctx_id, cmd_slice);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_create_fence(ptr: &mut rutabaga, fence: &rutabaga_fence) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.create_fence(*fence);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}
