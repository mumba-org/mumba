// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/mock_ethernet_eap_provider.h"

namespace shill {

MockEthernetEapProvider::MockEthernetEapProvider()
    : EthernetEapProvider(nullptr) {}

MockEthernetEapProvider::~MockEthernetEapProvider() = default;

}  // namespace shill
