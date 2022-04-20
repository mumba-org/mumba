// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_PROXY_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemProxy : public ModemProxyInterface {
 public:
  MockModemProxy();
  MockModemProxy(const MockModemProxy&) = delete;
  MockModemProxy& operator=(const MockModemProxy&) = delete;

  ~MockModemProxy() override;

  // Inherited methods from ModemProxyInterface.
  MOCK_METHOD(void,
              Enable,
              (bool, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void,
              CreateBearer,
              (const KeyValueStore&, Error*, const RpcIdentifierCallback&, int),
              (override));
  MOCK_METHOD(void,
              DeleteBearer,
              (const RpcIdentifier&, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void, Reset, (Error*, const ResultCallback&, int), (override));
  MOCK_METHOD(void,
              FactoryReset,
              (const std::string&, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void,
              SetCurrentCapabilities,
              (uint32_t, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void,
              SetCurrentModes,
              (uint32_t, uint32_t, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(
      void,
      SetCurrentBands,
      (const std::vector<uint32_t>&, Error*, const ResultCallback&, int),
      (override));
  MOCK_METHOD(void,
              SetPrimarySimSlot,
              (uint32_t, const ResultCallback&, int),
              (override));
  MOCK_METHOD(
      void,
      Command,
      (const std::string&, uint32_t, Error*, const StringCallback&, int),
      (override));
  MOCK_METHOD(void,
              SetPowerState,
              (uint32_t, Error*, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void,
              set_state_changed_callback,
              (const ModemStateChangedSignalCallback&),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_PROXY_H_
