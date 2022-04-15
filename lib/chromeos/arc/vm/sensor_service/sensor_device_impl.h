// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_SENSOR_SERVICE_SENSOR_DEVICE_IMPL_H_
#define ARC_VM_SENSOR_SERVICE_SENSOR_DEVICE_IMPL_H_

#include <memory>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "arc/vm/sensor_service/sensor_data_forwarder.h"
#include "arc/vm/sensor_service/sensor_service.mojom.h"

namespace arc {

// The arc::mojom::SensorDevice implementation.
class SensorDeviceImpl : public mojom::SensorDevice {
 public:
  SensorDeviceImpl(const base::FilePath& iio_sysfs_dir,
                   const base::FilePath& device_file);
  ~SensorDeviceImpl() override;
  SensorDeviceImpl(const SensorDeviceImpl&) = delete;
  SensorDeviceImpl& operator=(const SensorDeviceImpl&) = delete;

  // Binds the request to this object.
  void Bind(mojo::PendingReceiver<mojom::SensorDevice> receiver);

  // mojom::SensorDevice overrides:
  void GetAttribute(const std::string& name,
                    GetAttributeCallback callback) override;
  void SetAttribute(const std::string& name,
                    const std::string& value,
                    SetAttributeCallback callback) override;
  void OpenBuffer(OpenBufferCallback callback) override;

 private:
  const base::FilePath iio_sysfs_dir_;
  const base::FilePath device_file_;
  mojo::ReceiverSet<mojom::SensorDevice> receivers_;

  std::unique_ptr<SensorDataForwarder> data_forwarder_;
};

}  // namespace arc

#endif  // ARC_VM_SENSOR_SERVICE_SENSOR_DEVICE_IMPL_H_
