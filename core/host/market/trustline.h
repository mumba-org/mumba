// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_TRUSTLINE_H_
#define MUMBA_HOST_MARKET_TRUSTLINE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class Ledger;

class Trustline {
public:
  Trustline();
  ~Trustline();

  int64_t GetBalance() const;
  bool AddBalance(Ledger* ledger, int64_t delta);
  int64_t GetBuyingLiabilities(Ledger* ledger);
  int64_t GetSellingLiabilities(Ledger* ledger);
  int64_t AddBuyingLiabilities(Ledger* ledger, int64_t delta);
  int64_t AddSellingLiabilities(Ledger* ledger, int64_t delta);
  bool IsAuthorized() const;
  bool IsAuthorizedToMaintainLiabilities() const;
  bool IsClawbackEnabled() const;
  int64_t GetAvailableBalance(Ledger* ledger) const;
  int64_t GetMaxAmountReceive(Ledger* ledger) const;
  void Deactivate();
  
private:
  DISALLOW_COPY_AND_ASSIGN(Trustline);
};

}

#endif