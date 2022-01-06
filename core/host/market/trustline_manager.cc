// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/trustline_manager.h"

#include "core/host/market/market_manager.h"

namespace host {

TrustlineManager::TrustlineManager(MarketManager* market_manager): market_manager_(market_manager) {
  
}

TrustlineManager::~TrustlineManager() {
  
}

}