// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sqldb_drop_command.h"

std::unique_ptr<SqlDbDropCommand> SqlDbDropCommand::Create() {
  return std::make_unique<SqlDbDropCommand>();
}

SqlDbDropCommand::SqlDbDropCommand() {

}

SqlDbDropCommand::~SqlDbDropCommand() {

}

std::string SqlDbDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SqlDbDrop";
}


int SqlDbDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}