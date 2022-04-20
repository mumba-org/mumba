// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_sim_proxy.h"

#include "shill/testing.h"

using testing::_;

namespace shill {
namespace mm1 {

MockSimProxy::MockSimProxy() {
  ON_CALL(*this, SendPin(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, SendPuk(_, _, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<2>());
  ON_CALL(*this, EnablePin(_, _, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<2>());
  ON_CALL(*this, ChangePin(_, _, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<2>());
}

MockSimProxy::~MockSimProxy() = default;

}  // namespace mm1
}  // namespace shill
