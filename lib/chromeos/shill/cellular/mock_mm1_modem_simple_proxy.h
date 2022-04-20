// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_SIMPLE_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_SIMPLE_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_simple_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemSimpleProxy : public ModemSimpleProxyInterface {
 public:
  MockModemSimpleProxy();
  MockModemSimpleProxy(const MockModemSimpleProxy&) = delete;
  MockModemSimpleProxy& operator=(const MockModemSimpleProxy&) = delete;

  ~MockModemSimpleProxy() override;

  MOCK_METHOD(void,
              Connect,
              (const KeyValueStore&, const RpcIdentifierCallback&, int),
              (override));
  MOCK_METHOD(void,
              Disconnect,
              (const RpcIdentifier&, const ResultCallback&, int),
              (override));
  MOCK_METHOD(void, GetStatus, (const KeyValueStoreCallback&, int), (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_SIMPLE_PROXY_H_
