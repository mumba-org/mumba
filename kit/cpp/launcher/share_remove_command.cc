// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_remove_command.h"

std::unique_ptr<ShareRemoveCommand> ShareRemoveCommand::Create() {
  return std::make_unique<ShareRemoveCommand>();
}

ShareRemoveCommand::ShareRemoveCommand() {

}

ShareRemoveCommand::~ShareRemoveCommand() {

}

std::string ShareRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareRemove";
}


int ShareRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}