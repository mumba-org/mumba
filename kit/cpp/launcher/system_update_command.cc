// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/system_update_command.h"

std::unique_ptr<SystemUpdateCommand> SystemUpdateCommand::Create() {
  return std::make_unique<SystemUpdateCommand>();
}

SystemUpdateCommand::SystemUpdateCommand() {

}

SystemUpdateCommand::~SystemUpdateCommand() {

}

std::string SystemUpdateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SystemUpdate";
}


int SystemUpdateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}