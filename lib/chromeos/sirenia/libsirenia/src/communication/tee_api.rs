// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines the API provided to TEE apps through manatee-runtime.

use std::result::Result as StdResult;

use sirenia_rpc_macros::sirenia_rpc;

use crate::communication::persistence;

#[sirenia_rpc]
pub trait TeeApi<E> {
    // Storage.
    fn read_data(&mut self, id: String) -> StdResult<(persistence::Status, Vec<u8>), E>;
    fn remove(&mut self, id: String) -> StdResult<persistence::Status, E>;
    fn write_data(&mut self, id: String, data: Vec<u8>) -> StdResult<persistence::Status, E>;
}
