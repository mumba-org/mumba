// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_icmp_session.h"

namespace shill {

MockIcmpSession::MockIcmpSession(EventDispatcher* dispatcher)
    : IcmpSession(dispatcher) {}

MockIcmpSession::~MockIcmpSession() = default;

}  // namespace shill
