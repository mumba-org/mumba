// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/credential_drop_command.h"

std::unique_ptr<CredentialDropCommand> CredentialDropCommand::Create() {
  return std::make_unique<CredentialDropCommand>();
}

CredentialDropCommand::CredentialDropCommand() {

}

CredentialDropCommand::~CredentialDropCommand() {

}

std::string CredentialDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CredentialDrop";
}


int CredentialDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}