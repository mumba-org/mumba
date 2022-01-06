// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sqldb_list_command.h"

std::unique_ptr<SqlDbListCommand> SqlDbListCommand::Create() {
  return std::make_unique<SqlDbListCommand>();
}

SqlDbListCommand::SqlDbListCommand() {

}

SqlDbListCommand::~SqlDbListCommand() {

}

std::string SqlDbListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SqlDbList";
}


int SqlDbListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}