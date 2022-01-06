// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/credential_list_command.h"

std::unique_ptr<CredentialListCommand> CredentialListCommand::Create() {
  return std::make_unique<CredentialListCommand>();
}

CredentialListCommand::CredentialListCommand() {

}

CredentialListCommand::~CredentialListCommand() {

}

std::string CredentialListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CredentialList";
}


int CredentialListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}