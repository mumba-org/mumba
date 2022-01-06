// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/schema_create_command.h"

std::unique_ptr<SchemaCreateCommand> SchemaCreateCommand::Create() {
  return std::make_unique<SchemaCreateCommand>();
}

SchemaCreateCommand::SchemaCreateCommand() {

}

SchemaCreateCommand::~SchemaCreateCommand() {

}

std::string SchemaCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SchemaCreate";
}


int SchemaCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}