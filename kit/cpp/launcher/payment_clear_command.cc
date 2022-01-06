// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/payment_clear_command.h"

std::unique_ptr<PaymentClearCommand> PaymentClearCommand::Create() {
  return std::make_unique<PaymentClearCommand>();
}

PaymentClearCommand::PaymentClearCommand() {

}

PaymentClearCommand::~PaymentClearCommand() {

}

std::string PaymentClearCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PaymentClear";
}


int PaymentClearCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}