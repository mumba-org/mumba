// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_kvdb_get_command.h"

std::unique_ptr<ShareKvDbGetCommand> ShareKvDbGetCommand::Create() {
  return std::make_unique<ShareKvDbGetCommand>();
}

ShareKvDbGetCommand::ShareKvDbGetCommand() {

}

ShareKvDbGetCommand::~ShareKvDbGetCommand() {

}

std::string ShareKvDbGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareKvDbGet";
}


int ShareKvDbGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}