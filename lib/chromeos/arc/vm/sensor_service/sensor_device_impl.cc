// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/sensor_service/sensor_device_impl.h"

#include <fcntl.h>
#include <unistd.h>

#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_util.h>
#include <mojo/public/cpp/system/platform_handle.h>

namespace arc {

namespace {

// Returns the path of the specified attribute under |iio_sysfs_dir|.
base::FilePath GetAttributePath(const base::FilePath& iio_sysfs_dir,
                                const std::string& name) {
  base::FilePath path = iio_sysfs_dir.Append(name);
  if (!path.IsAbsolute() || path.ReferencesParent()) {
    LOG(ERROR) << "Invalid path: " << path.value();
    return {};
  }
  return path;
}

}  // namespace

SensorDeviceImpl::SensorDeviceImpl(const base::FilePath& iio_sysfs_dir,
                                   const base::FilePath& device_file)
    : iio_sysfs_dir_(iio_sysfs_dir), device_file_(device_file) {
  receivers_.set_disconnect_handler(base::BindRepeating(
      []() { LOG(INFO) << "SensorDevice connection closed."; }));
}
SensorDeviceImpl::~SensorDeviceImpl() = default;

void SensorDeviceImpl::Bind(
    mojo::PendingReceiver<mojom::SensorDevice> receiver) {
  receivers_.Add(this, std::move(receiver));
}

void SensorDeviceImpl::GetAttribute(const std::string& name,
                                    GetAttributeCallback callback) {
  // Read /sys/bus/iio/devices/iio:deviceX/<name>.
  base::FilePath path = GetAttributePath(iio_sysfs_dir_, name);
  if (path.empty()) {
    LOG(ERROR) << "Invalid name: " << name;
    std::move(callback).Run(mojom::AttributeIOResult::ERROR_IO, {});
    return;
  }
  std::string value;
  if (!base::ReadFileToString(path, &value)) {
    LOG(ERROR) << "Failed to read " << path.value();
    std::move(callback).Run(mojom::AttributeIOResult::ERROR_IO, {});
    return;
  }
  value = std::string(base::TrimString(value, "\n", base::TRIM_TRAILING));
  std::move(callback).Run(mojom::AttributeIOResult::SUCCESS, std::move(value));
}

void SensorDeviceImpl::SetAttribute(const std::string& name,
                                    const std::string& value,
                                    SetAttributeCallback callback) {
  // Write /sys/bus/iio/devices/iio:deviceX/<name>.
  base::FilePath path = GetAttributePath(iio_sysfs_dir_, name);
  if (path.empty()) {
    LOG(ERROR) << "Invalid name: " << name;
    std::move(callback).Run(mojom::AttributeIOResult::ERROR_IO);
    return;
  }
  if (!base::WriteFile(path, value.data(), value.size())) {
    LOG(ERROR) << "Failed to write " << path.value() << ", value = " << value;
    std::move(callback).Run(mojom::AttributeIOResult::ERROR_IO);
    return;
  }
  std::move(callback).Run(mojom::AttributeIOResult::SUCCESS);
}

void SensorDeviceImpl::OpenBuffer(OpenBufferCallback callback) {
  // Open /dev/iio:deviceX.
  base::ScopedFD device_fd(
      HANDLE_EINTR(open(device_file_.value().c_str(), O_RDONLY)));
  if (!device_fd.is_valid()) {
    PLOG(ERROR) << "open failed: " << device_file_.value();
    std::move(callback).Run({});
    return;
  }
  // Create a pipe.
  int pipe_fds[2];
  if (pipe(pipe_fds) < 0) {
    PLOG(ERROR) << "pipe failed";
    std::move(callback).Run({});
    return;
  }
  base::ScopedFD pipe_read_end(pipe_fds[0]), pipe_write_end(pipe_fds[1]);
  // The device file cannot cross the VM boundary. Instead, we return a pipe
  // from this method.
  // Data read from the device file will be forwarded to the pipe.
  auto data_forwarder = std::make_unique<SensorDataForwarder>(
      std::move(device_fd), std::move(pipe_write_end));
  if (!data_forwarder->Init()) {
    LOG(ERROR) << "Failed to initialize data forwarder.";
    std::move(callback).Run({});
    return;
  }
  data_forwarder_ = std::move(data_forwarder);
  // Return the pipe read end to the caller.
  std::move(callback).Run(mojo::WrapPlatformFile(std::move(pipe_read_end)));
}

}  // namespace arc
