// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/payment_manager.h"

#include "core/host/market/market_manager.h"

namespace host {

PaymentManager::PaymentManager(MarketManager* market_manager): market_manager_(market_manager) {

}

PaymentManager::~PaymentManager() {

}

Payment* PaymentManager::CreatePayment(const base::UUID& id) {
   return nullptr;
}

Payment* PaymentManager::GetPayment(const base::UUID& id) const {
   return nullptr;   
}

std::vector<Payment*> PaymentManager::GetPaymentList() const {
  return std::vector<Payment*>();
}

}