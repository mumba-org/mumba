// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_device.h"

#include <string>

#include <base/memory/ref_counted.h>
#include <gmock/gmock.h>

namespace shill {

class ControlInterface;
class EventDispatcher;

using ::testing::DefaultValue;

MockDevice::MockDevice(Manager* manager,
                       const std::string& link_name,
                       const std::string& address,
                       int interface_index)
    : Device(
          manager, link_name, address, interface_index, Technology::kUnknown) {
  DefaultValue<Technology>::Set(Technology::kUnknown);
  ON_CALL(*this, connection())
      .WillByDefault(testing::Return(Device::connection()));
}

MockDevice::~MockDevice() = default;

}  // namespace shill
