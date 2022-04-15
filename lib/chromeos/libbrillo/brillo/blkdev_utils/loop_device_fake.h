// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_LOOP_DEVICE_FAKE_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_LOOP_DEVICE_FAKE_H_

#include <memory>
#include <vector>

#include <brillo/blkdev_utils/loop_device.h>

namespace brillo {
namespace fake {

struct LoopDev {
  bool valid;
  base::FilePath backing_file;
  struct loop_info64 info;
};

class BRILLO_EXPORT FakeLoopDeviceManager : public brillo::LoopDeviceManager {
 public:
  FakeLoopDeviceManager();
  ~FakeLoopDeviceManager() override = default;
  std::unique_ptr<LoopDevice> AttachDeviceToFile(
      const base::FilePath& backing_file) override;

 private:
  std::vector<std::unique_ptr<LoopDevice>> SearchLoopDevicePaths(
      int device_number = -1) override;
};

}  // namespace fake
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_LOOP_DEVICE_FAKE_H_
