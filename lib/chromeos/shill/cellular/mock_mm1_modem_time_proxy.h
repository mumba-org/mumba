// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_TIME_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_TIME_PROXY_H_

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_time_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemTimeProxy : public ModemTimeProxyInterface {
 public:
  MockModemTimeProxy();
  MockModemTimeProxy(const MockModemTimeProxy&) = delete;
  MockModemTimeProxy& operator=(const MockModemTimeProxy&) = delete;

  ~MockModemTimeProxy() override;

  // Inherited methods from ModemTimeProxyInterface.
  MOCK_METHOD(void,
              GetNetworkTime,
              (Error*, const StringCallback&, int),
              (override));
  MOCK_METHOD(void,
              set_network_time_changed_callback,
              (const NetworkTimeChangedSignalCallback&),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_TIME_PROXY_H_
