// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/system_version_command.h"

std::unique_ptr<SystemVersionCommand> SystemVersionCommand::Create() {
  return std::make_unique<SystemVersionCommand>();
}

SystemVersionCommand::SystemVersionCommand() {

}

SystemVersionCommand::~SystemVersionCommand() {

}

std::string SystemVersionCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SystemVersion";
}


int SystemVersionCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}