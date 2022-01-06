// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/device_dispatcher_host.h"

namespace host {

DeviceDispatcherHost::DeviceDispatcherHost(): device_host_binding_(this) {

}

DeviceDispatcherHost::~DeviceDispatcherHost() {

}

common::mojom::DeviceManager* DeviceDispatcherHost::GetDeviceManagerInterface() {
  return device_interface_.get();
}

void DeviceDispatcherHost::AddBinding(common::mojom::DeviceDispatcherHostAssociatedRequest request) {
  // bind here on IO or on UI?
  device_host_binding_.Bind(std::move(request));
}

void DeviceDispatcherHost::Noop() {
  
}

}