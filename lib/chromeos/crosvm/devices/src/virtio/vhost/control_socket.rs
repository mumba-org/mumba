// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::{Deserialize, Serialize};

use base::Error as SysError;

#[derive(Serialize, Deserialize, Debug)]
pub enum VhostDevRequest {
    /// Mask or unmask all the MSI entries for a Virtio Vhost device.
    MsixChanged,
    /// Mask or unmask a MSI entry for a Virtio Vhost device.
    MsixEntryChanged(usize),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VhostDevResponse {
    Ok,
    Err(SysError),
}
