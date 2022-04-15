// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DEVICE_DEVICE_MANAGER_H_
#define MUMBA_HOST_DEVICE_DEVICE_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/data/resource.h"
#include "core/host/device/device_model.h"
#include "core/host/device/device.h"

namespace host {
class Workspace;

class DeviceManager : public ResourceManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnDevicesLoad(int r, int count) {}
    virtual void OnDeviceAdded(Device* device) {}
    virtual void OnDeviceRemoved(Device* device) {}
  };
  DeviceManager(scoped_refptr<Workspace> workspace);
  ~DeviceManager() override;

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

  // ResourceManager 
  bool HaveResource(const base::UUID& id) override {
    return devices()->DeviceExists(id);
  }

  bool HaveResource(const std::string& name) override {
    return devices()->DeviceExists(name);
  }

  Resource* GetResource(const base::UUID& id) override {
    return devices()->GetDeviceById(id);
  }

  Resource* GetResource(const std::string& name) override {
    return devices()->GetDevice(name);
  }

  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:

  void OnLoad(int r, int count);

  void NotifyDeviceAdded(Device* device);
  void NotifyDeviceRemoved(Device* device);
  void NotifyDevicesLoad(int r, int count);

  scoped_refptr<Workspace> workspace_;
  std::unique_ptr<DeviceModel> devices_;
  std::vector<Observer*> observers_;

  DISALLOW_COPY_AND_ASSIGN(DeviceManager);
};

}

#endif
