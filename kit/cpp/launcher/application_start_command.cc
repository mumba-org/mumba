// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_start_command.h"

std::unique_ptr<ApplicationStartCommand> ApplicationStartCommand::Create() {
  return std::make_unique<ApplicationStartCommand>();
}

ApplicationStartCommand::ApplicationStartCommand() {
  
}

ApplicationStartCommand::~ApplicationStartCommand() {

}

std::string ApplicationStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationStart";
}

int ApplicationStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}