// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/device/device_manager.h"

#include "base/bind.h"
#include "base/callback.h"
#include "core/host/device/device_model.h"
#include "core/host/device/device.h"

namespace host {

DeviceManager::DeviceManager() {

}

DeviceManager::~DeviceManager() {
  
}

void DeviceManager::Init() {
  devices_->Load(base::Bind(&DeviceManager::OnLoad, base::Unretained(this)));
}

void DeviceManager::Shutdown() {
  devices_.reset();
}

void DeviceManager::InsertDevice(std::unique_ptr<Device> device) {
  devices_->InsertDevice(device->id(), std::move(device));
}

void DeviceManager::RemoveDevice(Device* device) {
  devices_->RemoveDevice(device->id());
}

void DeviceManager::RemoveDevice(const base::UUID& uuid) {
  devices_->RemoveDevice(uuid);
}

void DeviceManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void DeviceManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void DeviceManager::OnLoad(int r, int count) {
  NotifyDevicesLoad(r, count);
}

void DeviceManager::NotifyDeviceAdded(Device* device) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDeviceAdded(device);
  }
}

void DeviceManager::NotifyDeviceRemoved(Device* device) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDeviceRemoved(device);
  }
}

void DeviceManager::NotifyDevicesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDevicesLoad(r, count);
  }
}

}