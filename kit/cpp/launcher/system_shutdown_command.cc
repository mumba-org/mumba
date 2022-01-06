// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/system_shutdown_command.h"

std::unique_ptr<SystemShutdownCommand> SystemShutdownCommand::Create() {
  return std::make_unique<SystemShutdownCommand>();
}

SystemShutdownCommand::SystemShutdownCommand() {

}

SystemShutdownCommand::~SystemShutdownCommand() {

}

std::string SystemShutdownCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SystemShutdown";
}


int SystemShutdownCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}