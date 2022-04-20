// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_cellular.h"

#include <gmock/gmock.h>

#include "shill/error.h"

namespace shill {

// TODO(rochberg): The cellular constructor does work.  Ought to fix
// this so that we don't depend on passing real values in for Type.

MockCellular::MockCellular(Manager* manager,
                           const std::string& link_name,
                           const std::string& address,
                           int interface_index,
                           Type type,
                           const std::string& service,
                           const RpcIdentifier& path)
    : Cellular(
          manager, link_name, address, interface_index, type, service, path) {}

MockCellular::~MockCellular() = default;

}  // namespace shill
