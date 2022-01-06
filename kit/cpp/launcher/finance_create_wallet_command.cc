// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/finance_create_wallet_command.h"

std::unique_ptr<FinanceCreateWalletCommand> FinanceCreateWalletCommand::Create() {
  return std::make_unique<FinanceCreateWalletCommand>();
}

FinanceCreateWalletCommand::FinanceCreateWalletCommand() {

}

FinanceCreateWalletCommand::~FinanceCreateWalletCommand() {

}

std::string FinanceCreateWalletCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FinanceCreateWallet";
}


int FinanceCreateWalletCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}