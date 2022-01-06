// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/identity_get_command.h"

std::unique_ptr<IdentityGetCommand> IdentityGetCommand::Create() {
  return std::make_unique<IdentityGetCommand>();
}

IdentityGetCommand::IdentityGetCommand() {

}

IdentityGetCommand::~IdentityGetCommand() {

}

std::string IdentityGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IdentityGet";
}


int IdentityGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}