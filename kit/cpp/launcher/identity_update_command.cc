// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/identity_update_command.h"

std::unique_ptr<IdentityUpdateCommand> IdentityUpdateCommand::Create() {
  return std::make_unique<IdentityUpdateCommand>();
}

IdentityUpdateCommand::IdentityUpdateCommand() {

}

IdentityUpdateCommand::~IdentityUpdateCommand() {

}

std::string IdentityUpdateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IdentityUpdate";
}


int IdentityUpdateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}