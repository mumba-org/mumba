// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_ACCOUNT_MANAGER_H_
#define MUMBA_HOST_MARKET_ACCOUNT_MANAGER_H_

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class Account;
class MarketManager;

class AccountManager {
public:
  AccountManager(MarketManager* market_manager);
  ~AccountManager();

  MarketManager* market_manager() const {
    return market_manager_;
  }

  Account* CreateAccount(const base::UUID& id);

private:

  MarketManager* market_manager_;

  DISALLOW_COPY_AND_ASSIGN(AccountManager);
};

}

#endif