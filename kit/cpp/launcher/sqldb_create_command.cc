// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sqldb_create_command.h"

std::unique_ptr<SqlDbCreateCommand> SqlDbCreateCommand::Create() {
  return std::make_unique<SqlDbCreateCommand>();
}

SqlDbCreateCommand::SqlDbCreateCommand() {

}

SqlDbCreateCommand::~SqlDbCreateCommand() {

}

std::string SqlDbCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SqlDbCreate";
}


int SqlDbCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}