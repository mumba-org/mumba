// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_MOCK_VPN_DRIVER_H_
#define SHILL_VPN_MOCK_VPN_DRIVER_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/vpn/vpn_driver.h"

namespace shill {

class MockVPNDriver : public VPNDriver {
 public:
  MockVPNDriver();
  MockVPNDriver(const MockVPNDriver&) = delete;
  MockVPNDriver& operator=(const MockVPNDriver&) = delete;

  ~MockVPNDriver() override;

  MOCK_METHOD(base::TimeDelta, ConnectAsync, (EventHandler*), (override));
  MOCK_METHOD(void, Disconnect, (), (override));
  MOCK_METHOD(void, OnConnectTimeout, (), (override));
  MOCK_METHOD(IPConfig::Properties, GetIPProperties, (), (const, override));
  MOCK_METHOD(bool,
              Load,
              (const StoreInterface*, const std::string&),
              (override));
  MOCK_METHOD(bool,
              Save,
              (StoreInterface*, const std::string&, bool),
              (override));
  MOCK_METHOD(void, UnloadCredentials, (), (override));
  MOCK_METHOD(void, InitPropertyStore, (PropertyStore*), (override));
  MOCK_METHOD(std::string, GetProviderType, (), (const, override));
  MOCK_METHOD(std::string, GetHost, (), (const, override));
  MOCK_METHOD(void,
              OnDefaultPhysicalServiceEvent,
              (DefaultPhysicalServiceEvent),
              (override));
};

class MockVPNDriverEventHandler : public VPNDriver::EventHandler {
 public:
  MockVPNDriverEventHandler();
  MockVPNDriverEventHandler(const MockVPNDriverEventHandler&) = delete;
  MockVPNDriverEventHandler& operator=(const MockVPNDriverEventHandler&) =
      delete;
  ~MockVPNDriverEventHandler();

  MOCK_METHOD(void, OnDriverConnected, (const std::string&, int), (override));
  MOCK_METHOD(void,
              OnDriverFailure,
              (Service::ConnectFailure, const std::string&),
              (override));
  MOCK_METHOD(void, OnDriverReconnecting, (base::TimeDelta), (override));
};

}  // namespace shill

#endif  // SHILL_VPN_MOCK_VPN_DRIVER_H_
