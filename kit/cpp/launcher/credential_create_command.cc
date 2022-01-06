// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/credential_create_command.h"

std::unique_ptr<CredentialCreateCommand> CredentialCreateCommand::Create() {
  return std::make_unique<CredentialCreateCommand>();
}

CredentialCreateCommand::CredentialCreateCommand() {

}

CredentialCreateCommand::~CredentialCreateCommand() {

}

std::string CredentialCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CredentialCreate";
}


int CredentialCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}