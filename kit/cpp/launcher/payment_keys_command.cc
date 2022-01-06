// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/payment_keys_command.h"

std::unique_ptr<PaymentKeysCommand> PaymentKeysCommand::Create() {
  return std::make_unique<PaymentKeysCommand>();
}

PaymentKeysCommand::PaymentKeysCommand() {

}

PaymentKeysCommand::~PaymentKeysCommand() {

}

std::string PaymentKeysCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PaymentKeys";
}


int PaymentKeysCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}