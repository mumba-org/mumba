// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_LEDGER_ENTRY_H_
#define MUMBA_HOST_MARKET_LEDGER_ENTRY_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "third_party/stellar/src/xdr/Stellar-ledger-entries.h"

namespace host {
class AccountEntry;
class TrustlineEntry;
class OfferEntry;
class DataEntry;
class ClaimableBalanceEntry;
class LiquidityPoolEntry;

class LedgerEntry {
public:

  static char kClassName[];

  static std::unique_ptr<LedgerEntry> Create(stellar::LedgerEntry entry);

  virtual ~LedgerEntry();

  const base::UUID& id() const {
    return id_;
  }

  stellar::LedgerEntryType type() const;

  uint32_t last_modified_ledger_sequence() const {
    return entry_.lastModifiedLedgerSeq;
  }
  
  // helpers
  bool is_account() const {
    return type() == stellar::LedgerEntryType::ACCOUNT;
  }

  bool is_trustline() const {
    return type() == stellar::LedgerEntryType::TRUSTLINE; 
  }
  
  bool is_offer() const {
    return type() == stellar::LedgerEntryType::OFFER;  
  }
  
  bool is_data() const {
    return type() == stellar::LedgerEntryType::DATA;   
  }
  
  bool is_claimable_balance() const {
    return type() == stellar::LedgerEntryType::CLAIMABLE_BALANCE;
  }
  
  bool is_liquidity_pool() const {
    return type() == stellar::LedgerEntryType::LIQUIDITY_POOL;       
  }

  AccountEntry* AsAccount();
  TrustlineEntry* AsTrustline();
  OfferEntry* AsOffer();
  DataEntry* AsData();
  ClaimableBalanceEntry* AsClaimableBalance();
  LiquidityPoolEntry* AsLiquidityPool();
  
protected:
  
  LedgerEntry(stellar::LedgerEntry entry);

  stellar::LedgerEntry entry_;

private:
 
  base::UUID id_;

  DISALLOW_COPY_AND_ASSIGN(LedgerEntry);
};


class AccountEntry : public LedgerEntry {
public:
  AccountEntry(stellar::LedgerEntry entry);
  ~AccountEntry() override; 

  const stellar::PublicKey& account_id() const {
    return entry_.data.account().accountID;
  }
  
  int64_t balance() const {
    return entry_.data.account().balance;
  }
  
  int64_t sequence_number() const {
    return entry_.data.account().seqNum;
  }

  uint32_t num_subentries() const {
    return entry_.data.account().numSubEntries;
  }
  
  stellar::PublicKey* inflation_dest() const {
    return entry_.data.account().inflationDest.get();
  }

  uint32_t flags() const {
    return entry_.data.account().flags;
  }

  const std::string& home_domain() const {
    return entry_.data.account().homeDomain;
  }

  const std::array<uint8_t, 4>& thresholds() const {
    return entry_.data.account().thresholds;
  }

   
  const std::vector<stellar::Signer>& signers() const {
    return entry_.data.account().signers;
  }

  const stellar::Liabilities& liabilities() const {
    return entry_.data.account().ext.v1().liabilities;
  }

  uint32_t num_sponsored() const {
    return entry_.data.account().ext.v1().ext.v2().numSponsored;
  }

  uint32_t num_sponsoring() const {
    return entry_.data.account().ext.v1().ext.v2().numSponsoring;
  }
   
  const xdr::xvector<stellar::SponsorshipDescriptor, stellar::MAX_SIGNERS>& signer_sponsoring_ids() const {
    return entry_.data.account().ext.v1().ext.v2().signerSponsoringIDs;
  }

};

class TrustlineEntry : public LedgerEntry {
public:
  TrustlineEntry(stellar::LedgerEntry entry);
  ~TrustlineEntry() override;

  const stellar::PublicKey& account_id() const {
    return entry_.data.trustLine().accountID;
  }

  const stellar::TrustLineAsset& asset() const {
    return entry_.data.trustLine().asset;
  }

  int64_t balance() const {
    return entry_.data.trustLine().balance;
  }  

  int64_t limit() const {
    return entry_.data.trustLine().limit;
  }

  uint32_t flags() const {
    return entry_.data.trustLine().flags; 
  }

  const stellar::Liabilities& liabilities() const {
    return entry_.data.trustLine().ext.v1().liabilities;
  }

  int32_t liquidity_pool_use_count() const {
    return entry_.data.trustLine().ext.v1().ext.v2().liquidityPoolUseCount;
  }

};


class OfferEntry : public LedgerEntry {
public:
  OfferEntry(stellar::LedgerEntry entry);
  ~OfferEntry() override;

  const stellar::PublicKey& seller_id() const {
    return entry_.data.offer().sellerID;
  }

  int64_t offer_id() const {
    return entry_.data.offer().offerID;
  }

  const stellar::Asset& selling() const {
    return entry_.data.offer().selling;
  }

  const stellar::Asset& buying() const {
    return entry_.data.offer().buying; 
  }

  int64_t amount() const {
    return entry_.data.offer().amount;
  }

  const stellar::Price& price() const {
    return entry_.data.offer().price;
  }

  uint32_t flags() const {
    return entry_.data.offer().flags;
  }

};

class DataEntry : public LedgerEntry {
public:
  DataEntry(stellar::LedgerEntry entry);
  ~DataEntry() override;

  const stellar::PublicKey& account_id() const {
    return entry_.data.data().accountID;
  }
  
  const xdr::xstring<64>& data_name() const {
    return entry_.data.data().dataName;
  }

  const xdr::xvector<uint8_t, 64>& data_value() const {
    return entry_.data.data().dataValue;
  }
};

class ClaimableBalanceEntry : public LedgerEntry {
public:
  ClaimableBalanceEntry(stellar::LedgerEntry entry);
  ~ClaimableBalanceEntry() override;

  const stellar::ClaimableBalanceID& balance_id() const {
    return entry_.data.claimableBalance().balanceID;
  }

  const xdr::xvector<stellar::Claimant,10>& claimants() const {
    return entry_.data.claimableBalance().claimants;
  }

  const stellar::Asset& asset() const {
    return entry_.data.claimableBalance().asset;
  }
  
  int64_t amount() const {
    return entry_.data.claimableBalance().amount;
  }

};

class LiquidityPoolEntry : public LedgerEntry {
public:
  LiquidityPoolEntry(stellar::LedgerEntry entry);
  ~LiquidityPoolEntry() override;

  const stellar::Hash& liquidity_pool_id() const {
    return entry_.data.liquidityPool().liquidityPoolID;
  }
  
  // 'constant product' is the only one
  stellar::LiquidityPoolType type() const {
    return entry_.data.liquidityPool().body.type();
  }

  // constant product

  const stellar::Asset& asset_a() const {
    return entry_.data.liquidityPool().body.constantProduct().params.assetA;
  }

  const stellar::Asset& asset_b() const {
    return entry_.data.liquidityPool().body.constantProduct().params.assetB;  
  }
  
  int32_t fee() const {
    return entry_.data.liquidityPool().body.constantProduct().params.fee;
  }

  int64_t reserve_a() const {
    return entry_.data.liquidityPool().body.constantProduct().reserveA;
  }

  int64_t reserve_b() const {
    return entry_.data.liquidityPool().body.constantProduct().reserveB;
  }

  int64_t total_pool_shares() const {
    return entry_.data.liquidityPool().body.constantProduct().totalPoolShares;
  }

  int64_t pool_shares_trust_line_count() const {
    return entry_.data.liquidityPool().body.constantProduct().poolSharesTrustLineCount;
  }
  
};

}

#endif