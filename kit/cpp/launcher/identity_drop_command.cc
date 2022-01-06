// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/identity_drop_command.h"

std::unique_ptr<IdentityDropCommand> IdentityDropCommand::Create() {
  return std::make_unique<IdentityDropCommand>();
}

IdentityDropCommand::IdentityDropCommand() {

}

IdentityDropCommand::~IdentityDropCommand() {

}

std::string IdentityDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IdentityDrop";
}


int IdentityDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}