// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DEVICE_DEVICE_MANAGER_H_
#define MUMBA_HOST_DEVICE_DEVICE_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class DeviceModel;
class Device;

class DeviceManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnDevicesLoad(int r, int count) {}
    virtual void OnDeviceAdded(Device* device) {}
    virtual void OnDeviceRemoved(Device* device) {}
  };
  DeviceManager();
  ~DeviceManager();

  DeviceModel* devices() const {
    return devices_.get();
  }

  void Init();
  void Shutdown();

  void InsertDevice(std::unique_ptr<Device> device);
  void RemoveDevice(Device* device);
  void RemoveDevice(const base::UUID& uuid);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:

  void OnLoad(int r, int count);

  void NotifyDeviceAdded(Device* device);
  void NotifyDeviceRemoved(Device* device);
  void NotifyDevicesLoad(int r, int count);

  std::unique_ptr<DeviceModel> devices_;
  std::vector<Observer*> observers_;

  DISALLOW_COPY_AND_ASSIGN(DeviceManager);
};

}

#endif
