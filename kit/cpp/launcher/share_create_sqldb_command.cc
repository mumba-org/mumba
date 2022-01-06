// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_create_sqldb_command.h"

std::unique_ptr<ShareCreateSqlDbCommand> ShareCreateSqlDbCommand::Create() {
  return std::make_unique<ShareCreateSqlDbCommand>();
}

ShareCreateSqlDbCommand::ShareCreateSqlDbCommand() {

}

ShareCreateSqlDbCommand::~ShareCreateSqlDbCommand() {

}

std::string ShareCreateSqlDbCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareCreateSqlDb";
}


int ShareCreateSqlDbCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}