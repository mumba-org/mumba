// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_create_kvdb_command.h"

std::unique_ptr<ShareCreateKvDbCommand> ShareCreateKvDbCommand::Create() {
  return std::make_unique<ShareCreateKvDbCommand>();
}

ShareCreateKvDbCommand::ShareCreateKvDbCommand() {

}

ShareCreateKvDbCommand::~ShareCreateKvDbCommand() {

}

std::string ShareCreateKvDbCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareCreateKvDb";
}


int ShareCreateKvDbCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}