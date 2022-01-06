// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DEVICE_DISPATCHER_H_
#define MUMBA_DOMAIN_DEVICE_DISPATCHER_H_

#include "base/macros.h"

#include "core/shared/common/mojom/device.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class DeviceDispatcher : public common::mojom::DeviceManager {
public:
  DeviceDispatcher();
  ~DeviceDispatcher() override;

  void Bind(common::mojom::DeviceManagerAssociatedRequest request);

  void AddDevice(const std::string& dev_name, AddDeviceCallback callback) override;
  void RemoveDevice(const std::string& dev_name, RemoveDeviceCallback callback) override;
  void GetDeviceList(GetDeviceListCallback callback) override;

private:

  mojo::AssociatedBinding<common::mojom::DeviceManager> binding_;

  DISALLOW_COPY_AND_ASSIGN(DeviceDispatcher);
};

}

#endif