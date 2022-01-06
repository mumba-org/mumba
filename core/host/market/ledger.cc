// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/ledger.h"

#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"

namespace host {

char Ledger::kClassName[] = "ledger";


Ledger::Ledger(stellar::LedgerHeader header):
  id_(base::UUID::generate()),
  header_(std::move(header)) {
  
}

Ledger::~Ledger() {
  
}

uint32_t Ledger::ledger_version() const {
  return header_.ledgerVersion;
}

stellar::Hash Ledger::previous_ledger_hash() const {
  return header_.previousLedgerHash;
}

stellar::StellarValue Ledger::scp_value() const {
  return header_.scpValue;
}

stellar::Hash Ledger::tx_set_result_hash() const {
  return header_.txSetResultHash;
}

stellar::Hash Ledger::bucket_list_hash() const {
  return header_.bucketListHash;
}

uint32_t Ledger::ledger_sequence() const {
  return header_.ledgerSeq;
}

int64_t Ledger::total_coins() const {
  return header_.totalCoins;
}

int64_t Ledger::fee_pool() const {
  return header_.feePool;
}

uint32_t Ledger::inflation_sequence() const {
  return header_.inflationSeq;
}

uint64_t Ledger::id_pool() const {
  return header_.idPool;
}

uint32_t Ledger::base_fee() const {
  return header_.baseFee;
}

uint32_t Ledger::base_reserve() const {
  return header_.baseReserve;
}

uint32_t Ledger::max_tx_set_size() const {
  return header_.maxTxSetSize;
}

xdr::xarray<stellar::Hash, 4> Ledger::skip_list() const {
  return header_.skipList;
}

stellar::LedgerHeader::_ext_t Ledger::ext() const {
  return header_.ext;
}

}
