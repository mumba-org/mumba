// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! renderer_utils: Utility functions and structs used by virgl_renderer and gfxstream.

use std::os::raw::{c_int, c_void};
use std::panic::catch_unwind;
use std::process::abort;

use base::{IntoRawDescriptor, SafeDescriptor};

use crate::rutabaga_utils::{
    RutabagaError, RutabagaFence, RutabagaFenceHandler, RutabagaResult, RUTABAGA_FLAG_FENCE,
};

#[cfg(feature = "gfxstream")]
use crate::rutabaga_utils::RUTABAGA_FLAG_INFO_RING_IDX;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VirglBox {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}

pub fn ret_to_res(ret: i32) -> RutabagaResult<()> {
    match ret {
        0 => Ok(()),
        _ => Err(RutabagaError::ComponentError(ret)),
    }
}

pub struct VirglCookie {
    pub render_server_fd: Option<SafeDescriptor>,
    pub fence_handler: Option<RutabagaFenceHandler>,
}

pub unsafe extern "C" fn write_fence(cookie: *mut c_void, fence: u32) {
    catch_unwind(|| {
        assert!(!cookie.is_null());
        let cookie = &*(cookie as *mut VirglCookie);

        // Call fence completion callback
        if let Some(handler) = &cookie.fence_handler {
            handler.call(RutabagaFence {
                flags: RUTABAGA_FLAG_FENCE,
                fence_id: fence as u64,
                ctx_id: 0,
                ring_idx: 0,
            });
        }
    })
    .unwrap_or_else(|_| abort())
}

#[cfg(feature = "gfxstream")]
pub extern "C" fn write_context_fence(
    cookie: *mut c_void,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
) {
    catch_unwind(|| {
        assert!(!cookie.is_null());
        let cookie = unsafe { &*(cookie as *mut VirglCookie) };

        // Call fence completion callback
        if let Some(handler) = &cookie.fence_handler {
            handler.call(RutabagaFence {
                flags: RUTABAGA_FLAG_FENCE | RUTABAGA_FLAG_INFO_RING_IDX,
                fence_id,
                ctx_id,
                ring_idx,
            });
        }
    })
    .unwrap_or_else(|_| abort())
}

#[allow(dead_code)]
pub unsafe extern "C" fn get_server_fd(cookie: *mut c_void, version: u32) -> c_int {
    catch_unwind(|| {
        assert!(!cookie.is_null());
        let cookie = &mut *(cookie as *mut VirglCookie);

        if version != 0 {
            return -1;
        }

        // Transfer the fd ownership to virglrenderer.
        cookie
            .render_server_fd
            .take()
            .map(SafeDescriptor::into_raw_descriptor)
            .unwrap_or(-1)
    })
    .unwrap_or_else(|_| abort())
}
