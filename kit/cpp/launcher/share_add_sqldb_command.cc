// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_add_sqldb_command.h"

std::unique_ptr<ShareAddSqlDbCommand> ShareAddSqlDbCommand::Create() {
  return std::make_unique<ShareAddSqlDbCommand>();
}

ShareAddSqlDbCommand::ShareAddSqlDbCommand() {

}

ShareAddSqlDbCommand::~ShareAddSqlDbCommand() {

}

std::string ShareAddSqlDbCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareAddSqlDb";
}


int ShareAddSqlDbCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}