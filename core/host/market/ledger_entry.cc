// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/ledger_entry.h"

#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"

namespace host {

char LedgerEntry::kClassName[] = "ledger-entry";

// static 
std::unique_ptr<LedgerEntry> LedgerEntry::Create(stellar::LedgerEntry entry) {
  switch (entry.data.type()) {
    case stellar::LedgerEntryType::ACCOUNT:
      return std::make_unique<AccountEntry>(std::move(entry));
    case stellar::LedgerEntryType::TRUSTLINE:
      return std::make_unique<TrustlineEntry>(std::move(entry));
    case stellar::LedgerEntryType::OFFER:  
      return std::make_unique<OfferEntry>(std::move(entry));
    case stellar::LedgerEntryType::DATA:
      return std::make_unique<DataEntry>(std::move(entry));
    case stellar::LedgerEntryType::CLAIMABLE_BALANCE:
      return std::make_unique<ClaimableBalanceEntry>(std::move(entry));
    case stellar::LedgerEntryType::LIQUIDITY_POOL:
      return std::make_unique<LiquidityPoolEntry>(std::move(entry));
  }
  // unreacheable
  return std::unique_ptr<LedgerEntry>();
}

LedgerEntry::LedgerEntry(stellar::LedgerEntry entry):
  entry_(std::move(entry)),
  id_(base::UUID::generate()) {
  
}

LedgerEntry::~LedgerEntry() {
  
}

stellar::LedgerEntryType LedgerEntry::type() const {
  return entry_.data.type();
}

AccountEntry* LedgerEntry::AsAccount() {
  DCHECK(is_account());
  return static_cast<AccountEntry*>(this);
}

TrustlineEntry* LedgerEntry::AsTrustline() {
  DCHECK(is_trustline());
  return static_cast<TrustlineEntry*>(this);
}

OfferEntry* LedgerEntry::AsOffer() {
  DCHECK(is_offer());
  return static_cast<OfferEntry*>(this);
}

DataEntry* LedgerEntry::AsData() {
  DCHECK(is_data());
  return static_cast<DataEntry*>(this);
}

ClaimableBalanceEntry* LedgerEntry::AsClaimableBalance() {
  DCHECK(is_claimable_balance());
  return static_cast<ClaimableBalanceEntry*>(this);
}

LiquidityPoolEntry* LedgerEntry::AsLiquidityPool() {
  DCHECK(is_liquidity_pool());
  return static_cast<LiquidityPoolEntry*>(this);
}

AccountEntry::AccountEntry(stellar::LedgerEntry entry): LedgerEntry(std::move(entry)) {
  
}

AccountEntry::~AccountEntry() {
  
}

TrustlineEntry::TrustlineEntry(stellar::LedgerEntry entry): LedgerEntry(std::move(entry)) {
  
}

TrustlineEntry::~TrustlineEntry() {
  
}

OfferEntry::OfferEntry(stellar::LedgerEntry entry): LedgerEntry(std::move(entry)) {
  
}

OfferEntry::~OfferEntry() {
  
}

DataEntry::DataEntry(stellar::LedgerEntry entry): LedgerEntry(std::move(entry)) {
  
}

DataEntry::~DataEntry() {
  
}

ClaimableBalanceEntry::ClaimableBalanceEntry(stellar::LedgerEntry entry): LedgerEntry(std::move(entry)) {
  
}

ClaimableBalanceEntry::~ClaimableBalanceEntry() {
  
}

LiquidityPoolEntry::LiquidityPoolEntry(stellar::LedgerEntry entry): LedgerEntry(std::move(entry)) {
  
}

LiquidityPoolEntry::~LiquidityPoolEntry() {
  
}

}
