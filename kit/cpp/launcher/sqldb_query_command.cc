// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sqldb_query_command.h"

std::unique_ptr<SqlDbQueryCommand> SqlDbQueryCommand::Create() {
  return std::make_unique<SqlDbQueryCommand>();
}

SqlDbQueryCommand::SqlDbQueryCommand() {

}

SqlDbQueryCommand::~SqlDbQueryCommand() {

}

std::string SqlDbQueryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SqlDbQuery";
}


int SqlDbQueryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}