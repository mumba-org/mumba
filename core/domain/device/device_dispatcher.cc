// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/device/device_dispatcher.h"

namespace domain {

DeviceDispatcher::DeviceDispatcher():
 binding_(this) {}
 
DeviceDispatcher::~DeviceDispatcher() {}

void DeviceDispatcher::Bind(common::mojom::DeviceManagerAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void DeviceDispatcher::AddDevice(const std::string& dev_name, AddDeviceCallback callback) {

}

void DeviceDispatcher::RemoveDevice(const std::string& dev_name, RemoveDeviceCallback callback) {

}

void DeviceDispatcher::GetDeviceList(GetDeviceListCallback callback) {

}

}