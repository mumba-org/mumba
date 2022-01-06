// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/payment_list_command.h"

std::unique_ptr<PaymentListCommand> PaymentListCommand::Create() {
  return std::make_unique<PaymentListCommand>();
}

PaymentListCommand::PaymentListCommand() {

}

PaymentListCommand::~PaymentListCommand() {

}

std::string PaymentListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PaymentList";
}


int PaymentListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}