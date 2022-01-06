// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DEVICE_DEVICE_MODEL_H_
#define MUMBA_HOST_DEVICE_DEVICE_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"

namespace host {
class Device;

class DeviceModel {
public:
  DeviceModel();
  ~DeviceModel();

  const std::vector<std::unique_ptr<Device>>& devices() const {
    return devices_;
  }

  std::vector<std::unique_ptr<Device>>& devices() {
    return devices_;
  }

  void Load(base::Callback<void(int, int)> cb);
  bool DeviceExists(Device* device) const;
  Device* GetDeviceById(const base::UUID& id);
  void InsertDevice(const base::UUID& id, std::unique_ptr<Device> device);
  void RemoveDevice(const base::UUID& id);
 
  void Close();

private:
  
  void InsertDeviceInternal(const base::UUID& id, std::unique_ptr<Device> device);
  void RemoveDeviceInternal(const base::UUID& id);

  void AddToCache(const base::UUID& id, std::unique_ptr<Device> device);
  void RemoveFromCache(const base::UUID& id);
  void RemoveFromCache(Device* device);
 
  std::vector<std::unique_ptr<Device>> devices_;

  DISALLOW_COPY_AND_ASSIGN(DeviceModel);
};

}

#endif