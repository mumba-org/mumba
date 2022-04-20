// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_modem_modemcdma_proxy.h"

#include "shill/testing.h"

using testing::_;

namespace shill {
namespace mm1 {

MockModemModemCdmaProxy::MockModemModemCdmaProxy() {
  ON_CALL(*this, Activate(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, ActivateManual(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
}

MockModemModemCdmaProxy::~MockModemModemCdmaProxy() = default;

}  // namespace mm1
}  // namespace shill
