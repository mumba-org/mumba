// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_LEDGER_H_
#define MUMBA_HOST_MARKET_LEDGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"

#include "third_party/stellar/src/xdr/Stellar-ledger.h"

namespace host {

class Ledger {
public:

  static char kClassName[];

  Ledger(stellar::LedgerHeader header);
  ~Ledger();

  const base::UUID& id() const {
    return id_;
  }
  
  // the protocol version of the ledger
  uint32_t ledger_version() const;
  // hash of the previous ledger header
  stellar::Hash previous_ledger_hash() const;
  // what consensus agreed to
  stellar::StellarValue scp_value() const;
  // the TransactionResultSet that led to this ledger
  stellar::Hash tx_set_result_hash() const;
  // hash of the ledger state
  stellar::Hash bucket_list_hash() const;
  // sequence number of this ledger
  uint32_t ledger_sequence() const;
  // total number of stroops in existence.
  // 10,000,000 stroops in 1 XLM
  int64_t total_coins() const;
  // fees burned since last inflation run
  int64_t fee_pool() const;
  // inflation sequence number
  uint32_t inflation_sequence() const;
  // last used global ID, used for generating objects
  uint64_t id_pool() const;
  // base fee per operation in stroops
  uint32_t base_fee() const;
  // account base reserve in stroops
  uint32_t base_reserve() const;
  // maximum size a transaction set can be
  uint32_t max_tx_set_size() const;
  // hashes of ledgers in the past. allows you to jump back
  // in time without walking the chain back ledger by ledger
  // each slot contains the oldest ledger that is mod of
  // either 50  5000  50000 or 500000 depending on index
  // skipList[0] mod(50), skipList[1] mod(5000), etc
  xdr::xarray<stellar::Hash, 4> skip_list() const;
  // reserved for future use
  stellar::LedgerHeader::_ext_t ext() const;

private:
  
  base::UUID id_;
  stellar::LedgerHeader header_;

  DISALLOW_COPY_AND_ASSIGN(Ledger);
};

}

#endif