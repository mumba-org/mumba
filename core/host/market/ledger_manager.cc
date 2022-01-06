// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/ledger_manager.h"

#include "base/strings/string_util.h"
#include "core/host/market/ledger.h"
#include "core/host/market/market_manager.h"
#include "third_party/stellar/src/ledger/LedgerManager.h"
#include "third_party/stellar/src/crypto/ShortHash.h"
#include "third_party/stellar/src/util/RandHasher.h"
#include "third_party/stellar/src/util/Logging.h"
#include "third_party/stellar/src/main/ApplicationUtils.h"
#include "third_party/stellar/src/history/HistoryArchiveManager.h"
#include "third_party/stellar/src/main/Config.h"
#include "third_party/xdrpp/xdrpp/marshal.h"

namespace host {

LedgerManager::LedgerManager(MarketManager* market_manager):
  market_manager_(market_manager), 
  genesis_ledger_(nullptr) {
} 

LedgerManager::~LedgerManager() {

}

// Ledger* LedgerManager::GetLedger(uint32_t ledger_sequence) {
//   // warning: check if theres no problem accessing this manager from other thread
//   //          as we might have thread safety issues here, if it doesnt
//   Ledger* ledger = GetCachedLedger(ledger_sequence);
//   if (!ledger) {
//     ledger = ledger_main_->getLedgerManager(). ?
//   }
//   return nullptr;
// }

Ledger* LedgerManager::genesis_ledger() {
  return GetCachedGenesisLedger();
}

uint32_t LedgerManager::GetLastClosedLedgerSequence() const {
  return market_manager_->GetLedgerManager().getLastClosedLedgerNum();
}

int64_t LedgerManager::GetMinimumBalanceToCreateNewEntry(uint32_t count) {
  return market_manager_->GetLedgerManager().getLastMinBalance(count);
}

Ledger* LedgerManager::GetCachedGenesisLedger() {
  // lazy loading
  if (!genesis_ledger_) {
    stellar::LedgerHeader genesis = stellar::LedgerManager::genesisLedger();
    genesis_ledger_ = AddLedgerToCache(std::move(genesis));
  }
  return genesis_ledger_;
}

Ledger* LedgerManager::GetCachedLedger(uint32_t ledger_sequence) {
  auto found = ledgers_.find(ledger_sequence);
  if (found != ledgers_.end()) {
    return found->second.get();
  }
  return nullptr;
}

Ledger* LedgerManager::AddLedgerToCache(stellar::LedgerHeader ledger_header) {
  std::unique_ptr<Ledger> ledger = std::make_unique<Ledger>(std::move(ledger_header));
  Ledger* result = ledger.get();
  ledgers_.emplace(result->ledger_sequence(), std::move(ledger));
  return result;
}

}