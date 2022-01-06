// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_read_command.h"

std::unique_ptr<ShareReadCommand> ShareReadCommand::Create() {
  return std::make_unique<ShareReadCommand>();
}

ShareReadCommand::ShareReadCommand() {

}

ShareReadCommand::~ShareReadCommand() {

}

std::string ShareReadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareRead";
}


int ShareReadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}