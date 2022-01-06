// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_PAYMENT_MANAGER_H_
#define MUMBA_HOST_MARKET_PAYMENT_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class MarketManager;
class Payment;

class PaymentManager {
public:
  PaymentManager(MarketManager* market_manager);
  ~PaymentManager();

  MarketManager* market_manager() const {
    return market_manager_;
  }
  
  Payment* CreatePayment(const base::UUID& id);
  Payment* GetPayment(const base::UUID& id) const;
  std::vector<Payment*> GetPaymentList() const;

private:

  MarketManager* market_manager_;

  DISALLOW_COPY_AND_ASSIGN(PaymentManager);  
};

}

#endif