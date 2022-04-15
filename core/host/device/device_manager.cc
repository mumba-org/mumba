// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/device/device_manager.h"

#include "base/bind.h"
#include "base/callback.h"
#include "core/host/device/device_model.h"
#include "core/host/device/device.h"
#include "core/host/schema/schema.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/workspace/workspace.h"

namespace host {

DeviceManager::DeviceManager(scoped_refptr<Workspace> workspace): workspace_(workspace) {

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

const google::protobuf::Descriptor* DeviceManager::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Device");
}

std::string DeviceManager::resource_classname() const {
  return Device::kClassName;
}

}