// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/sensor_service/sensor_service_impl.h"

#include <dirent.h>
#include <unistd.h>

#include <utility>
#include <vector>

#include <base/logging.h>
#include <brillo/files/scoped_dir.h>

namespace arc {

namespace {

// IIO sysfs root directory.
constexpr char kIioDeviceDir[] = "/sys/bus/iio/devices/";

}  // namespace

SensorServiceImpl::SensorServiceImpl() = default;
SensorServiceImpl::~SensorServiceImpl() = default;

bool SensorServiceImpl::Initialize(
    mojo::PendingReceiver<mojom::SensorService> receiver) {
  // List the devices in the IIO sysfs.
  brillo::ScopedDIR dir(opendir(kIioDeviceDir));
  if (!dir.is_valid()) {
    PLOG(ERROR) << "Failed to open " << kIioDeviceDir;
    return false;
  }
  const struct dirent* ent = nullptr;
  while ((ent = readdir(dir.get()))) {
    if (ent->d_type == DT_LNK) {
      const std::string device_name = ent->d_name;
      const base::FilePath iio_sysfs_dir =
          base::FilePath(kIioDeviceDir).Append(device_name);
      // /sys/bus/iio/devices/iio:deviceX is paired with /dev/iio:deviceX.
      const base::FilePath device_file =
          base::FilePath("/dev").Append(device_name);

      devices_[device_name] =
          std::make_unique<SensorDeviceImpl>(iio_sysfs_dir, device_file);
    }
  }
  // Bind the request to this object.
  receiver_.Bind(std::move(receiver));
  receiver_.set_disconnect_handler(base::BindOnce(
      []() { LOG(ERROR) << "SensorService connection closed."; }));
  return true;
}

void SensorServiceImpl::GetDeviceNames(GetDeviceNamesCallback callback) {
  std::vector<std::string> device_names;
  for (const auto& device : devices_)
    device_names.push_back(device.first);
  std::move(callback).Run(std::move(device_names));
}

void SensorServiceImpl::GetDeviceByName(
    const std::string& name,
    mojo::PendingReceiver<mojom::SensorDevice> receiver) {
  auto it = devices_.find(name);
  if (it == devices_.end()) {
    // This will close the message pipe attached to the request and the
    // caller will be notified about the error by the connection error handler.
    LOG(ERROR) << "Device not found: " << name;
    return;
  }
  it->second->Bind(std::move(receiver));
}

}  // namespace arc
