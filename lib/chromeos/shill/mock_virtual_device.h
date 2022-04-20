// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_VIRTUAL_DEVICE_H_
#define SHILL_MOCK_VIRTUAL_DEVICE_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/virtual_device.h"

namespace shill {

class MockVirtualDevice : public VirtualDevice {
 public:
  MockVirtualDevice(Manager* manager,
                    const std::string& link_name,
                    int interface_index,
                    Technology technology);
  MockVirtualDevice(const MockVirtualDevice&) = delete;
  MockVirtualDevice& operator=(const MockVirtualDevice&) = delete;

  ~MockVirtualDevice() override;

  MOCK_METHOD(void,
              Stop,
              (Error*, const EnabledStateChangedCallback&),
              (override));
  MOCK_METHOD(void, UpdateIPConfig, (const IPConfig::Properties&), (override));
  MOCK_METHOD(void, DropConnection, (), (override));
  MOCK_METHOD(void, ResetConnection, (), (override));
  MOCK_METHOD(void, SetServiceState, (Service::ConnectState), (override));
  MOCK_METHOD(void, SetEnabled, (bool), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_VIRTUAL_DEVICE_H_
