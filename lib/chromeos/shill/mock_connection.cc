// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_connection.h"

#include "shill/ipconfig.h"

namespace shill {

MockConnection::MockConnection(const DeviceInfo* device_info)
    : Connection(0, std::string(), false, Technology::kUnknown, device_info) {}

MockConnection::~MockConnection() = default;

}  // namespace shill
