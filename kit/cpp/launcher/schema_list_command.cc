// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/schema_list_command.h"

std::unique_ptr<SchemaListCommand> SchemaListCommand::Create() {
  return std::make_unique<SchemaListCommand>();
}

SchemaListCommand::SchemaListCommand() {

}

SchemaListCommand::~SchemaListCommand() {

}

std::string SchemaListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SchemaList";
}


int SchemaListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}