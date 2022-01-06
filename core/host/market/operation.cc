// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/operation.h"

namespace host {

Operation::Operation(
    OperationType type,
    const stellar::MuxedAccount& source_account): 
      type_(type),
      source_account_(source_account) {

}

Operation::~Operation() {

}


CreateAccountOp::CreateAccountOp(stellar::CreateAccountOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CREATE_ACCOUNT, source_account), 
  op_(std::move(op)) {

}

CreateAccountOp::~CreateAccountOp() {

}

PaymentOp::PaymentOp(stellar::PaymentOp op, const stellar::MuxedAccount& source_account): 
  Operation(OperationType::PAYMENT, source_account), 
  op_(std::move(op)) {

}

PaymentOp::~PaymentOp() {

}

PathPaymentStrictReceiveOp::PathPaymentStrictReceiveOp(stellar::PathPaymentStrictReceiveOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::PATH_PAYMENT_STRICT_RECEIVE, source_account), 
  op_(std::move(op)) {

}

PathPaymentStrictReceiveOp::~PathPaymentStrictReceiveOp() {

}

ManageSellOfferOp::ManageSellOfferOp(stellar::ManageSellOfferOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::MANAGE_SELL_OFFER, source_account), 
  op_(std::move(op)) {
  
}

ManageSellOfferOp::~ManageSellOfferOp() {
  
}

CreatePassiveSellOfferOp::CreatePassiveSellOfferOp(stellar::CreatePassiveSellOfferOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CREATE_PASSIVE_SELL_OFFER, source_account), 
  op_(std::move(op)) {

}

CreatePassiveSellOfferOp::~CreatePassiveSellOfferOp() {

}

SetOptionsOp::SetOptionsOp(stellar::SetOptionsOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::SET_OPTIONS, source_account), 
  op_(std::move(op))  {

}

SetOptionsOp::~SetOptionsOp() {

}

ChangeTrustOp::ChangeTrustOp(stellar::ChangeTrustOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CHANGE_TRUST, source_account), 
  op_(std::move(op))  {

}

ChangeTrustOp::~ChangeTrustOp() {

}

AllowTrustOp::AllowTrustOp(stellar::AllowTrustOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::ALLOW_TRUST, source_account), 
  op_(std::move(op))  {

}

AllowTrustOp::~AllowTrustOp() {

}

AccountMergeOp::AccountMergeOp(const stellar::MuxedAccount& source_account):
  Operation(OperationType::ACCOUNT_MERGE, source_account)  {

}

AccountMergeOp::~AccountMergeOp() {

}

InflationOp::InflationOp(const stellar::MuxedAccount& source_account):
  Operation(OperationType::INFLATION, source_account)  {

}

InflationOp::~InflationOp() {

}

ManageDataOp::ManageDataOp(stellar::ManageDataOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::MANAGE_DATA, source_account), 
  op_(std::move(op))  {

}

ManageDataOp::~ManageDataOp() {

}

BumpSequenceOp::BumpSequenceOp(stellar::BumpSequenceOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::BUMP_SEQUENCE, source_account), 
  op_(std::move(op))  {

}

BumpSequenceOp::~BumpSequenceOp() {

}

ManageBuyOfferOp::ManageBuyOfferOp(stellar::ManageBuyOfferOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::MANAGE_BUY_OFFER, source_account), 
  op_(std::move(op))  {

}

ManageBuyOfferOp::~ManageBuyOfferOp() {

}

PathPaymentStrictSendOp::PathPaymentStrictSendOp(stellar::PathPaymentStrictSendOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::PATH_PAYMENT_STRICT_SEND, source_account), 
  op_(std::move(op)) {

}

PathPaymentStrictSendOp::~PathPaymentStrictSendOp() {

}

CreateClaimableBalanceOp::CreateClaimableBalanceOp(stellar::CreateClaimableBalanceOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CREATE_CLAIMABLE_BALANCE, source_account), 
  op_(std::move(op))  {

}

CreateClaimableBalanceOp::~CreateClaimableBalanceOp() {

}

ClaimClaimableBalanceOp::ClaimClaimableBalanceOp(stellar::ClaimClaimableBalanceOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CLAIM_CLAIMABLE_BALANCE, source_account), 
  op_(std::move(op))  {

}

ClaimClaimableBalanceOp::~ClaimClaimableBalanceOp() {

}

BeginSponsoringFutureReservesOp::BeginSponsoringFutureReservesOp(stellar::BeginSponsoringFutureReservesOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::BEGIN_SPONSORING_FUTURE_RESERVES, source_account), 
  op_(std::move(op))  {

}

BeginSponsoringFutureReservesOp::~BeginSponsoringFutureReservesOp() {

}

EndSponsoringFutureReservesOp::EndSponsoringFutureReservesOp(const stellar::MuxedAccount& source_account):
  Operation(OperationType::END_SPONSORING_FUTURE_RESERVES, source_account)  {

}

EndSponsoringFutureReservesOp::~EndSponsoringFutureReservesOp() {

}

RevokeSponsorshipOp::RevokeSponsorshipOp(stellar::RevokeSponsorshipOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::REVOKE_SPONSORSHIP, source_account), 
  op_(std::move(op))  {

}

RevokeSponsorshipOp::~RevokeSponsorshipOp() {

}

ClawbackOp::ClawbackOp(stellar::ClawbackOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CLAWBACK, source_account), 
  op_(std::move(op))  {

}

ClawbackOp::~ClawbackOp() {

}

ClawbackClaimableBalanceOp::ClawbackClaimableBalanceOp(stellar::ClawbackClaimableBalanceOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::CLAWBACK_CLAIMABLE_BALANCE, source_account), 
  op_(std::move(op))  {

}

ClawbackClaimableBalanceOp::~ClawbackClaimableBalanceOp() {

}

SetTrustLineFlagsOp::SetTrustLineFlagsOp(stellar::SetTrustLineFlagsOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::SET_TRUST_LINE_FLAGS, source_account), 
  op_(std::move(op))  {

}

SetTrustLineFlagsOp::~SetTrustLineFlagsOp() {

}

LiquidityPoolDepositOp::LiquidityPoolDepositOp(stellar::LiquidityPoolDepositOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::LIQUIDITY_POOL_DEPOSIT, source_account), 
  op_(std::move(op))  {

}

LiquidityPoolDepositOp::~LiquidityPoolDepositOp() {

}

LiquidityPoolWithdrawOp::LiquidityPoolWithdrawOp(stellar::LiquidityPoolWithdrawOp op, const stellar::MuxedAccount& source_account):
  Operation(OperationType::LIQUIDITY_POOL_WITHDRAW, source_account), 
  op_(std::move(op))  {

}

LiquidityPoolWithdrawOp::~LiquidityPoolWithdrawOp() {

}

}