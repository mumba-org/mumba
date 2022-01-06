// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/account_manager.h"

#include "core/host/market/market_manager.h"

namespace host {

AccountManager::AccountManager(MarketManager* market_manager): market_manager_(market_manager) {

}

AccountManager::~AccountManager() {

}

Account* AccountManager::CreateAccount(const base::UUID& id) {
   return nullptr; 
}

}