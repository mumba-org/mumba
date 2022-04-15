// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Ties together the various modules that make up the Sirenia library used by
//! both Trichechus and Dugong.

#![deny(unsafe_op_in_unsafe_fn)]

include!("bindings/include_modules.rs");

pub mod pstore;

use sys_util::error;

pub fn log_error<T, E: std::fmt::Debug>(ret: Result<T, E>) -> Result<T, E> {
    if let Err(err) = &ret {
        error!("Got error: {:?}", err);
    }
    ret
}
