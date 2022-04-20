// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_MOCK_DHCP_CONTROLLER_H_
#define SHILL_NETWORK_MOCK_DHCP_CONTROLLER_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/network/dhcp_controller.h"
#include "shill/technology.h"

namespace shill {

class MockDHCPController : public DHCPController {
 public:
  MockDHCPController(ControlInterface* control_interface,
                     const std::string& device_name);
  MockDHCPController(const MockDHCPController&) = delete;
  MockDHCPController& operator=(const MockDHCPController&) = delete;

  ~MockDHCPController() override;

  void ProcessEventSignal(const std::string& reason,
                          const KeyValueStore& configuration) override;

  MOCK_METHOD(bool, RequestIP, (), (override));
  MOCK_METHOD(bool, ReleaseIP, (ReleaseReason), (override));
  MOCK_METHOD(bool, RenewIP, (), (override));
  MOCK_METHOD(void, set_minimum_mtu, (int), (override));
};

}  // namespace shill

#endif  // SHILL_NETWORK_MOCK_DHCP_CONTROLLER_H_
