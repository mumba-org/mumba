// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_PAYMENT_H_
#define MUMBA_HOST_MARKET_PAYMENT_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"

namespace host {

// Remember: we already have a "BuyOrder" and "SellOrder" that is more tied
// to the ledger, so we will propably use those here    
class Payment {
public:
  Payment();
  ~Payment();

  void Cancel(base::Callback<void(int)> completion);
  void Refund(base::Callback<void(int)> completion);

private:

  DISALLOW_COPY_AND_ASSIGN(Payment);  
};

}

#endif