// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_kvdb_set_command.h"

std::unique_ptr<ShareKvDbSetCommand> ShareKvDbSetCommand::Create() {
  return std::make_unique<ShareKvDbSetCommand>();
}

ShareKvDbSetCommand::ShareKvDbSetCommand() {

}

ShareKvDbSetCommand::~ShareKvDbSetCommand() {

}

std::string ShareKvDbSetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareKvDbSet";
}


int ShareKvDbSetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}