// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/trustline.h"

namespace host {

Trustline::Trustline() {

}

Trustline::~Trustline() {

}

int64_t Trustline::GetBalance() const {
  return -1;
}

bool Trustline::AddBalance(Ledger* ledger, int64_t delta) {
  return false;
}

int64_t Trustline::GetBuyingLiabilities(Ledger* ledger) {
  return -1; 
}

int64_t Trustline::GetSellingLiabilities(Ledger* ledger) {
  return -1;
}

int64_t Trustline::AddBuyingLiabilities(Ledger* ledger, int64_t delta) {
  return -1;
}

int64_t Trustline::AddSellingLiabilities(Ledger* ledger, int64_t delta) {
  return -1;
}

bool Trustline::IsAuthorized() const {
  return false;
}

bool Trustline::IsAuthorizedToMaintainLiabilities() const {
  return false;
}

bool Trustline::IsClawbackEnabled() const {
  return false;
}

int64_t Trustline::GetAvailableBalance(Ledger* ledger) const {
  return -1;
}

int64_t Trustline::GetMaxAmountReceive(Ledger* ledger) const {
  return -1;
}

void Trustline::Deactivate() {

}

}