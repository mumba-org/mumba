// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/drop_sign_command.h"

std::unique_ptr<DropSignCommand> DropSignCommand::Create() {
  return std::make_unique<DropSignCommand>();
}

DropSignCommand::DropSignCommand() {

}
 
DropSignCommand::~DropSignCommand() {

}

std::string DropSignCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DropSign";
}

int DropSignCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}