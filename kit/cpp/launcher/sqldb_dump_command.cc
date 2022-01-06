// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sqldb_dump_command.h"

std::unique_ptr<SqlDbDumpCommand> SqlDbDumpCommand::Create() {
  return std::make_unique<SqlDbDumpCommand>();
}

SqlDbDumpCommand::SqlDbDumpCommand() {

}

SqlDbDumpCommand::~SqlDbDumpCommand() {

}

std::string SqlDbDumpCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SqlDbDump";
}


int SqlDbDumpCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}