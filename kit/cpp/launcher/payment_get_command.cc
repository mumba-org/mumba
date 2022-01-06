// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/payment_get_command.h"

std::unique_ptr<PaymentGetCommand> PaymentGetCommand::Create() {
  return std::make_unique<PaymentGetCommand>();
}

PaymentGetCommand::PaymentGetCommand() {

}

PaymentGetCommand::~PaymentGetCommand() {

}

std::string PaymentGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PaymentGet";
}


int PaymentGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}