// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/identity_create_command.h"

std::unique_ptr<IdentityCreateCommand> IdentityCreateCommand::Create() {
  return std::make_unique<IdentityCreateCommand>();
}

IdentityCreateCommand::IdentityCreateCommand() {

}

IdentityCreateCommand::~IdentityCreateCommand() {

}

std::string IdentityCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IdentityCreate";
}


int IdentityCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}