// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_WIFI_H_
#define SHILL_WIFI_MOCK_WIFI_H_

#include <string>

#include <base/memory/ref_counted.h>
#include <gmock/gmock.h>

#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/wifi/wake_on_wifi.h"
#include "shill/wifi/wifi.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

class Error;

class MockWiFi : public WiFi {
 public:
  // MockWiFi takes ownership of the wake_on_wifi pointer passed to it.
  // This is not exposed in the constructor type because gmock doesn't
  // provide the ability to forward arguments that aren't const &...
  MockWiFi(Manager* manager,
           const std::string& link_name,
           const std::string& address,
           int interface_index,
           WakeOnWiFiInterface* wake_on_wifi);
  MockWiFi(const MockWiFi&) = delete;
  MockWiFi& operator=(const MockWiFi&) = delete;

  ~MockWiFi() override;

  MOCK_METHOD(void,
              Start,
              (Error*, const EnabledStateChangedCallback&),
              (override));
  MOCK_METHOD(void,
              Stop,
              (Error*, const EnabledStateChangedCallback&),
              (override));
  MOCK_METHOD(void, Scan, (Error*, const std::string&), (override));
  MOCK_METHOD(void, DisconnectFromIfActive, (WiFiService*), (override));
  MOCK_METHOD(void, DisconnectFrom, (WiFiService*), (override));
  MOCK_METHOD(void, ClearCachedCredentials, (const WiFiService*), (override));
  MOCK_METHOD(void,
              ConnectTo,
              (WiFiService * service, Error* error),
              (override));
  MOCK_METHOD(bool, IsIdle, (), (const, override));
  MOCK_METHOD(void,
              NotifyEndpointChanged,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(bool, IsCurrentService, (const WiFiService* service), (const));
  MOCK_METHOD(void, DestroyIPConfigLease, (const std::string&), (override));
  MOCK_METHOD(bool, IsConnectedViaTether, (), (const, override));
  MOCK_METHOD(int16_t, GetSignalLevelForActiveService, (), (override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_WIFI_H_
