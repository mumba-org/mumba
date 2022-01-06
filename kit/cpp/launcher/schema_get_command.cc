// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/schema_get_command.h"

std::unique_ptr<SchemaGetCommand> SchemaGetCommand::Create() {
  return std::make_unique<SchemaGetCommand>();
}

SchemaGetCommand::SchemaGetCommand() {

}

SchemaGetCommand::~SchemaGetCommand() {

}

std::string SchemaGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SchemaGet";
}


int SchemaGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}