// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/payment_delete_command.h"

std::unique_ptr<PaymentDeleteCommand> PaymentDeleteCommand::Create() {
  return std::make_unique<PaymentDeleteCommand>();
}

PaymentDeleteCommand::PaymentDeleteCommand() {

}

PaymentDeleteCommand::~PaymentDeleteCommand() {

}

std::string PaymentDeleteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PaymentDelete";
}


int PaymentDeleteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}