// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_status_command.h"

std::unique_ptr<ShareStatusCommand> ShareStatusCommand::Create() {
  return std::make_unique<ShareStatusCommand>();
}

ShareStatusCommand::ShareStatusCommand() {

}

ShareStatusCommand::~ShareStatusCommand() {

}

std::string ShareStatusCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareStatus";
}


int ShareStatusCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}