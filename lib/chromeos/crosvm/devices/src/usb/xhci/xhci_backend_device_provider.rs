// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::super::host_backend::error::Result;
use super::usb_hub::UsbHub;
use crate::utils::{EventLoop, FailHandle};
use base::RawDescriptor;
use std::sync::Arc;

/// Xhci backend provider will run on an EventLoop and connect new devices to usb ports.
pub trait XhciBackendDeviceProvider: Send {
    /// Start the provider on EventLoop.
    fn start(
        &mut self,
        fail_handle: Arc<dyn FailHandle>,
        event_loop: Arc<EventLoop>,
        hub: Arc<UsbHub>,
    ) -> Result<()>;

    /// Keep raw descriptors that should be kept open.
    fn keep_rds(&self) -> Vec<RawDescriptor>;
}
