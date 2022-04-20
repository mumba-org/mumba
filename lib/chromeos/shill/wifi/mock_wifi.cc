// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/mock_wifi.h"

#include <memory>
#include <string>

namespace shill {

MockWiFi::MockWiFi(Manager* manager,
                   const std::string& link_name,
                   const std::string& address,
                   int interface_index,
                   WakeOnWiFiInterface* wake_on_wifi)
    : WiFi(manager,
           link_name,
           address,
           interface_index,
           std::unique_ptr<WakeOnWiFiInterface>(wake_on_wifi)) {}

MockWiFi::~MockWiFi() = default;

}  // namespace shill
