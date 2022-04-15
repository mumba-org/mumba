// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_SENSOR_SERVICE_SENSOR_SERVICE_IMPL_H_
#define ARC_VM_SENSOR_SERVICE_SENSOR_SERVICE_IMPL_H_

#include <map>
#include <memory>
#include <string>

#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "arc/vm/sensor_service/sensor_device_impl.h"
#include "arc/vm/sensor_service/sensor_service.mojom.h"

namespace arc {

// The arc::mojom::SensorService implementation.
class SensorServiceImpl : public mojom::SensorService {
 public:
  SensorServiceImpl();
  ~SensorServiceImpl() override;
  SensorServiceImpl(const SensorServiceImpl&) = delete;
  SensorServiceImpl& operator=(const SensorServiceImpl&) = delete;

  // Initializes this object.
  bool Initialize(mojo::PendingReceiver<mojom::SensorService> receiver);

  // mojom::SensorService overrides:
  void GetDeviceNames(GetDeviceNamesCallback callback) override;
  void GetDeviceByName(
      const std::string& name,
      mojo::PendingReceiver<mojom::SensorDevice> receiver) override;

 private:
  mojo::Receiver<mojom::SensorService> receiver_{this};

  // Map from device names to SensorDeviceImpl objects.
  std::map<std::string, std::unique_ptr<SensorDeviceImpl>> devices_;
};

}  // namespace arc

#endif  // ARC_VM_SENSOR_SERVICE_SENSOR_SERVICE_IMPL_H_
