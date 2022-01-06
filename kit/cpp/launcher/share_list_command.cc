// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_list_command.h"

std::unique_ptr<ShareListCommand> ShareListCommand::Create() {
  return std::make_unique<ShareListCommand>();
}

ShareListCommand::ShareListCommand() {

}

ShareListCommand::~ShareListCommand() {

}

std::string ShareListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareList";
}


int ShareListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}