// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_LEDGER_MANAGER_H_
#define MUMBA_HOST_MARKET_LEDGER_MANAGER_H_

#include <memory>
#include <unordered_map>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/synchronization/waitable_event.h"
#include "third_party/stellar/src/xdr/Stellar-ledger.h"

namespace host {
class MarketManager;
class Ledger;

class LedgerManager {
public:
  LedgerManager(MarketManager* market_manager);
  ~LedgerManager();

  MarketManager* market_manager() const {
    return market_manager_;
  }

  //Ledger* GetLedger(uint32_t ledger_sequence);

  Ledger* genesis_ledger();

  // Return the sequence number of the LCL.
  uint32_t GetLastClosedLedgerSequence() const;

  // Return the minimum balance required to establish, in the current ledger,
  // a new ledger entry with `ownerCount` owned objects.  Derived from the
  // current ledger's `baseReserve` value.
  int64_t GetMinimumBalanceToCreateNewEntry(uint32_t count);
  
private:

  Ledger* GetCachedGenesisLedger();
  Ledger* GetCachedLedger(uint32_t ledger_sequence);
  Ledger* AddLedgerToCache(stellar::LedgerHeader ledger);

  MarketManager* market_manager_;
  Ledger* genesis_ledger_;

  // this is basically a cache.. the real ledgers are stellar::LedgerHeader types
  // we keep those wrapped copies here only in case of requests
  std::unordered_map<uint32_t, std::unique_ptr<Ledger>> ledgers_;

  DISALLOW_COPY_AND_ASSIGN(LedgerManager);
};

}

#endif