// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/mock_wifi_provider.h"

// Needed for mock method instantiation.
#include "shill/profile.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi_service.h"

using testing::Return;

namespace shill {

MockWiFiProvider::MockWiFiProvider() : WiFiProvider(nullptr) {
  ON_CALL(*this, GetHiddenSSIDList()).WillByDefault(Return(ByteArrays()));
}

MockWiFiProvider::~MockWiFiProvider() = default;

}  // namespace shill
