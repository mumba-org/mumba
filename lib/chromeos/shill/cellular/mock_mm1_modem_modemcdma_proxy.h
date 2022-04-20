// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_MODEMCDMA_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_MODEMCDMA_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_modemcdma_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemModemCdmaProxy : public ModemModemCdmaProxyInterface {
 public:
  MockModemModemCdmaProxy();
  MockModemModemCdmaProxy(const MockModemModemCdmaProxy&) = delete;
  MockModemModemCdmaProxy& operator=(const MockModemModemCdmaProxy&) = delete;

  ~MockModemModemCdmaProxy() override;

  MOCK_METHOD(void,
              Activate,
              (const std::string&, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void,
              ActivateManual,
              (const KeyValueStore&, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void,
              set_activation_state_callback,
              (const ActivationStateSignalCallback&),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_MODEMCDMA_PROXY_H_
