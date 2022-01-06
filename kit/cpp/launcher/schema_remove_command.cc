// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/schema_remove_command.h"

std::unique_ptr<SchemaRemoveCommand> SchemaRemoveCommand::Create() {
  return std::make_unique<SchemaRemoveCommand>();
}

SchemaRemoveCommand::SchemaRemoveCommand() {

}

SchemaRemoveCommand::~SchemaRemoveCommand() {

}

std::string SchemaRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SchemaRemove";
}


int SchemaRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}