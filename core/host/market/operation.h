// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_OPERATION_H_
#define MUMBA_HOST_MARKET_OPERATION_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "third_party/stellar/src/xdr/Stellar-transaction.h"

namespace host {

enum class OperationType : int {
  CREATE_ACCOUNT = 0,
  PAYMENT = 1,
  PATH_PAYMENT_STRICT_RECEIVE = 2,
  MANAGE_SELL_OFFER = 3,
  CREATE_PASSIVE_SELL_OFFER = 4,
  SET_OPTIONS = 5,
  CHANGE_TRUST = 6,
  ALLOW_TRUST = 7,
  ACCOUNT_MERGE = 8,
  INFLATION = 9,
  MANAGE_DATA = 10,
  BUMP_SEQUENCE = 11,
  MANAGE_BUY_OFFER = 12,
  PATH_PAYMENT_STRICT_SEND = 13,
  CREATE_CLAIMABLE_BALANCE = 14,
  CLAIM_CLAIMABLE_BALANCE = 15,
  BEGIN_SPONSORING_FUTURE_RESERVES = 16,
  END_SPONSORING_FUTURE_RESERVES = 17,
  REVOKE_SPONSORSHIP = 18,
  CLAWBACK = 19,
  CLAWBACK_CLAIMABLE_BALANCE = 20,
  SET_TRUST_LINE_FLAGS = 21,
  LIQUIDITY_POOL_DEPOSIT = 22,
  LIQUIDITY_POOL_WITHDRAW = 23
};

class Operation {
public:
  
  virtual ~Operation();
  
  OperationType type() const {
    return type_;
  }

  const stellar::MuxedAccount& source_account() const { 
    return source_account_; 
  }
  
protected:

  Operation(OperationType type,
            const stellar::MuxedAccount& source_account);

private:
  
  OperationType type_;
  stellar::MuxedAccount source_account_;
  
  DISALLOW_COPY_AND_ASSIGN(Operation);
};

class CreateAccountOp : public Operation {
public:
  CreateAccountOp(stellar::CreateAccountOp op, const stellar::MuxedAccount& source_account);
  ~CreateAccountOp() override;

  // account to create
  const stellar::PublicKey& destination() const {
    return op_.destination;
  }

  int64_t starting_balance() const {
    return op_.startingBalance;
  }

private:
  
  stellar::CreateAccountOp op_;

  DISALLOW_COPY_AND_ASSIGN(CreateAccountOp);
};

class PaymentOp : public Operation {
  
  PaymentOp(stellar::PaymentOp op, const stellar::MuxedAccount& source_account);
  ~PaymentOp() override;

  const stellar::MuxedAccount& destination() const {
    return op_.destination; // recipient of the payment
  }

  const stellar::Asset& asset() const {
    return op_.asset;              // what they end up with
  }

  int64_t amount() const {
    return op_.amount;             // amount they end up with
  }

private:
  stellar::PaymentOp op_;

  DISALLOW_COPY_AND_ASSIGN(PaymentOp);
};

class PathPaymentStrictReceiveOp : public Operation {
public:
  PathPaymentStrictReceiveOp(stellar::PathPaymentStrictReceiveOp op, const stellar::MuxedAccount& source_account);
  ~PathPaymentStrictReceiveOp() override;

  // asset we pay with
  const stellar::Asset& send_asset() const {
    return op_.sendAsset;
  }

  // the maximum amount of sendAsset to
  // send (excluding fees).
  // The operation will fail if can't be met
  int64_t send_max() const {
    return op_.sendMax;
  }

  // recipient of the payment
  const stellar::MuxedAccount& destination() const {
    return op_.destination;
  }

  const stellar::Asset& dest_asset() const {
    return op_.destAsset;
  }

  // amount they end up with
  int64_t dest_amount() const {
    return op_.destAmount;
  }

  // additional hops it must go through to get there
  const xdr::xvector<stellar::Asset, 5>& path() const {
    return op_.path;
  }

private:
  
  stellar::PathPaymentStrictReceiveOp op_;

  DISALLOW_COPY_AND_ASSIGN(PathPaymentStrictReceiveOp);
};


class ManageSellOfferOp : public Operation {
public:
  ManageSellOfferOp(stellar::ManageSellOfferOp op, const stellar::MuxedAccount& source_account);
  ~ManageSellOfferOp() override;

  const stellar::Asset& selling() const {
    return op_.selling;
  }

  const stellar::Asset& buying() const {
    return op_.buying;
  }

  int64_t amount() const {
    return op_.amount;
  }

  const stellar::Price price() const {
    return op_.price; 
  }

  // 0 = create a new offer, otherwise edit an existing offer
  int64_t offer_id() const {
    return op_.offerID;
  }

private:
  
  stellar::ManageSellOfferOp op_;

  DISALLOW_COPY_AND_ASSIGN(ManageSellOfferOp);
};

class CreatePassiveSellOfferOp : public Operation {
public:
  CreatePassiveSellOfferOp(stellar::CreatePassiveSellOfferOp op, const stellar::MuxedAccount& source_account);
  ~CreatePassiveSellOfferOp() override;
private:
  stellar::CreatePassiveSellOfferOp op_;

  DISALLOW_COPY_AND_ASSIGN(CreatePassiveSellOfferOp);
};

class SetOptionsOp : public Operation {
public:
  SetOptionsOp(stellar::SetOptionsOp op, const stellar::MuxedAccount& source_account);
  ~SetOptionsOp() override;
private:
  stellar::SetOptionsOp op_;
  
  DISALLOW_COPY_AND_ASSIGN(SetOptionsOp);
};

class ChangeTrustOp : public Operation {
public:
  ChangeTrustOp(stellar::ChangeTrustOp op, const stellar::MuxedAccount& source_account);
  ~ChangeTrustOp() override;
private:
  stellar::ChangeTrustOp op_;

  DISALLOW_COPY_AND_ASSIGN(ChangeTrustOp);
};

class AllowTrustOp : public Operation {
public:
  AllowTrustOp(stellar::AllowTrustOp op, const stellar::MuxedAccount& source_account);
  ~AllowTrustOp() override;
private:

  stellar::AllowTrustOp op_;
  
  DISALLOW_COPY_AND_ASSIGN(AllowTrustOp);
};

class AccountMergeOp : public Operation {
public:
  AccountMergeOp(const stellar::MuxedAccount& source_account);
  ~AccountMergeOp() override;

private:

  DISALLOW_COPY_AND_ASSIGN(AccountMergeOp);
};

class InflationOp : public Operation {
public:
  InflationOp(const stellar::MuxedAccount& source_account);
  ~InflationOp() override;

private:

  DISALLOW_COPY_AND_ASSIGN(InflationOp);
};

class ManageDataOp : public Operation {
public:
  ManageDataOp(stellar::ManageDataOp op, const stellar::MuxedAccount& source_account);
  ~ManageDataOp() override;

private:
  
  stellar::ManageDataOp op_;

  DISALLOW_COPY_AND_ASSIGN(ManageDataOp);

};

class BumpSequenceOp : public Operation {
public:
  BumpSequenceOp(stellar::BumpSequenceOp op, const stellar::MuxedAccount& source_account);
  ~BumpSequenceOp() override;
private:

  stellar::BumpSequenceOp op_;

  DISALLOW_COPY_AND_ASSIGN(BumpSequenceOp);
};

class ManageBuyOfferOp : public Operation {
public:
  ManageBuyOfferOp(stellar::ManageBuyOfferOp op, const stellar::MuxedAccount& source_account);
  ~ManageBuyOfferOp() override;
private:

  stellar::ManageBuyOfferOp op_;

  DISALLOW_COPY_AND_ASSIGN(ManageBuyOfferOp);
};

class PathPaymentStrictSendOp : public Operation {
public:
  PathPaymentStrictSendOp(stellar::PathPaymentStrictSendOp op, const stellar::MuxedAccount& source_account);
  ~PathPaymentStrictSendOp() override;
  
  // asset we pay with
  const stellar::Asset& send_asset() const {
    return op_.sendAsset;
  }

  // amount of sendAsset to send (excluding fees)
  int64_t send_amount() const {
    return op_.sendAmount;
  }

  // recipient of the payment
  const stellar::MuxedAccount& destination() const {
    return op_.destination;
  }

  // what they end up with
  const stellar::Asset& dest_asset() const {
    return op_.destAsset;
  }

  // the minimum amount of dest asset to
  // be received
  // The operation will fail if it can't be met
  int64_t dest_min() const {
    return op_.destMin;
  }

  // additional hops it must go through to get there
  const xdr::xvector<stellar::Asset, 5>& path() const {
    return op_.path;
  }

private:

  stellar::PathPaymentStrictSendOp op_;

  DISALLOW_COPY_AND_ASSIGN(PathPaymentStrictSendOp);
};

class CreateClaimableBalanceOp : public Operation {
public:
  CreateClaimableBalanceOp(stellar::CreateClaimableBalanceOp op, const stellar::MuxedAccount& source_account);
  ~CreateClaimableBalanceOp() override;

private:
  stellar::CreateClaimableBalanceOp op_;
  DISALLOW_COPY_AND_ASSIGN(CreateClaimableBalanceOp);
};

class ClaimClaimableBalanceOp : public Operation {
public:
  ClaimClaimableBalanceOp(stellar::ClaimClaimableBalanceOp op, const stellar::MuxedAccount& source_account);
  ~ClaimClaimableBalanceOp() override;

private:
  
  stellar::ClaimClaimableBalanceOp op_;
  
  DISALLOW_COPY_AND_ASSIGN(ClaimClaimableBalanceOp);
};

class BeginSponsoringFutureReservesOp : public Operation {
public:
  BeginSponsoringFutureReservesOp(stellar::BeginSponsoringFutureReservesOp op, const stellar::MuxedAccount& source_account);
  ~BeginSponsoringFutureReservesOp() override;

private:

  stellar::BeginSponsoringFutureReservesOp op_;

  DISALLOW_COPY_AND_ASSIGN(BeginSponsoringFutureReservesOp);
};

class EndSponsoringFutureReservesOp : public Operation {
public:
  EndSponsoringFutureReservesOp(const stellar::MuxedAccount& source_account);
  ~EndSponsoringFutureReservesOp() override;

private:
  
  DISALLOW_COPY_AND_ASSIGN(EndSponsoringFutureReservesOp);
};

class RevokeSponsorshipOp : public Operation {
public:
  RevokeSponsorshipOp(stellar::RevokeSponsorshipOp op, const stellar::MuxedAccount& source_account);
  ~RevokeSponsorshipOp() override;

private:
  
  stellar::RevokeSponsorshipOp op_;

  DISALLOW_COPY_AND_ASSIGN(RevokeSponsorshipOp);
};

class ClawbackOp : public Operation {
public:
  ClawbackOp(stellar::ClawbackOp op, const stellar::MuxedAccount& source_account);
  ~ClawbackOp() override;

private:

  stellar::ClawbackOp op_;
  DISALLOW_COPY_AND_ASSIGN(ClawbackOp);
};

class ClawbackClaimableBalanceOp : public Operation {
public:
  ClawbackClaimableBalanceOp(stellar::ClawbackClaimableBalanceOp op, const stellar::MuxedAccount& source_account);
  ~ClawbackClaimableBalanceOp() override;

private:
  
  stellar::ClawbackClaimableBalanceOp op_;
  DISALLOW_COPY_AND_ASSIGN(ClawbackClaimableBalanceOp);
};

class SetTrustLineFlagsOp : public Operation {
public:
  SetTrustLineFlagsOp(stellar::SetTrustLineFlagsOp op, const stellar::MuxedAccount& source_account);
  ~SetTrustLineFlagsOp() override;

private:
  
  stellar::SetTrustLineFlagsOp op_;
  DISALLOW_COPY_AND_ASSIGN(SetTrustLineFlagsOp);
};

class LiquidityPoolDepositOp : public Operation {
public:
  LiquidityPoolDepositOp(stellar::LiquidityPoolDepositOp op, const stellar::MuxedAccount& source_account);
  ~LiquidityPoolDepositOp() override;

private:
  stellar::LiquidityPoolDepositOp op_;
  DISALLOW_COPY_AND_ASSIGN(LiquidityPoolDepositOp);
};

class LiquidityPoolWithdrawOp : public Operation {
public:
  LiquidityPoolWithdrawOp(stellar::LiquidityPoolWithdrawOp op, const stellar::MuxedAccount& source_account);
  ~LiquidityPoolWithdrawOp() override;

private:
  
  stellar::LiquidityPoolWithdrawOp op_;

  DISALLOW_COPY_AND_ASSIGN(LiquidityPoolWithdrawOp);
};


}

#endif