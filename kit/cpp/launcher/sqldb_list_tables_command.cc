// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sqldb_list_tables_command.h"

std::unique_ptr<SqlDbListTablesCommand> SqlDbListTablesCommand::Create() {
  return std::make_unique<SqlDbListTablesCommand>();
}

SqlDbListTablesCommand::SqlDbListTablesCommand() {

}

SqlDbListTablesCommand::~SqlDbListTablesCommand() {

}

std::string SqlDbListTablesCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SqlDbListTables";
}


int SqlDbListTablesCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}