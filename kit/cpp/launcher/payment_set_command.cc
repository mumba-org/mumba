// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/payment_set_command.h"

std::unique_ptr<PaymentSetCommand> PaymentSetCommand::Create() {
  return std::make_unique<PaymentSetCommand>();
}

PaymentSetCommand::PaymentSetCommand() {

}

PaymentSetCommand::~PaymentSetCommand() {

}

std::string PaymentSetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PaymentSet";
}


int PaymentSetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}