// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_modem_proxy.h"

#include "shill/testing.h"

using testing::_;

namespace shill {
namespace mm1 {

MockModemProxy::MockModemProxy() {
  ON_CALL(*this, Enable(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, CreateBearer(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, DeleteBearer(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, Reset(_, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<0>());
  ON_CALL(*this, FactoryReset(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, SetCurrentCapabilities(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, SetCurrentModes(_, _, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<2>());
  ON_CALL(*this, Command(_, _, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<2>());
  ON_CALL(*this, SetPowerState(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
}

MockModemProxy::~MockModemProxy() = default;

}  // namespace mm1
}  // namespace shill
