// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/system_status_command.h"

std::unique_ptr<SystemStatusCommand> SystemStatusCommand::Create() {
  return std::make_unique<SystemStatusCommand>();
}

SystemStatusCommand::SystemStatusCommand() {

}

SystemStatusCommand::~SystemStatusCommand() {

}

std::string SystemStatusCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SystemStatus";
}


int SystemStatusCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}