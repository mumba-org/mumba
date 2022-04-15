// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/device/device_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/device/device.h"
#include "core/host/workspace/workspace.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

DeviceModel::DeviceModel() {
  
}

DeviceModel::~DeviceModel() {
  devices_.clear();
}

void DeviceModel::Load(base::Callback<void(int, int)> cb) {
  std::move(cb).Run(net::OK, 0);
}

void DeviceModel::Close() {

}

void DeviceModel::InsertDevice(const base::UUID& id, std::unique_ptr<Device> device) {
  InsertDeviceInternal(id, std::move(device));
}

void DeviceModel::RemoveDevice(const base::UUID& id) {
  RemoveDeviceInternal(id);
}

void DeviceModel::InsertDeviceInternal(const base::UUID& id, std::unique_ptr<Device> device) {
  if (!DeviceExists(device.get())) {
    AddToCache(id, std::move(device));
  } else {
    LOG(ERROR) << "Failed to add device " << id.to_string() << " '" << device->name() << "'. Already exists";
  }
}

void DeviceModel::RemoveDeviceInternal(const base::UUID& id) {
  Device* device = GetDeviceById(id);
  if (device) {
    RemoveFromCache(device);
  } else {
    LOG(ERROR) << "Failed to remove device. Device with id " << id.to_string() << " not found.";
  }
}

Device* DeviceModel::GetDeviceById(const base::UUID& id) {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

Device* DeviceModel::GetDevice(const std::string& name) {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;
}

bool DeviceModel::DeviceExists(Device* device) const {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if (it->get() == device) {
      return true;
    }
  }
  return false; 
}

bool DeviceModel::DeviceExists(const std::string& name) const {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

bool DeviceModel::DeviceExists(const base::UUID& id) const {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false; 
}

void DeviceModel::AddToCache(const base::UUID& id, std::unique_ptr<Device> device) {
  device->set_managed(true);
  devices_.push_back(std::move(device));
}

void DeviceModel::RemoveFromCache(const base::UUID& id) {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if ((*it)->id() == id) {
      devices_.erase(it);
      return;
    }
  }
}

void DeviceModel::RemoveFromCache(Device* device) {
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if (it->get() == device) {
      devices_.erase(it);
      return;
    }
  }
}

}
