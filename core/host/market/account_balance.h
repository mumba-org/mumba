// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_ACCOUNT_BALANCE_H_
#define MUMBA_HOST_MARKET_ACCOUNT_BALANCE_H_

#include "base/macros.h"
#include "base/uuid.h"

namespace host {

/*
 * this is more of a POD for a account balance
 */
class AccountBalance {
public:
  AccountBalance();
  ~AccountBalance();

private:
  DISALLOW_COPY_AND_ASSIGN(AccountBalance);
};

}

#endif