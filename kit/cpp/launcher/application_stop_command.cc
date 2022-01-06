// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_stop_command.h"

std::unique_ptr<ApplicationStopCommand> ApplicationStopCommand::Create() {
  return std::make_unique<ApplicationStopCommand>();
}

ApplicationStopCommand::ApplicationStopCommand() {}

ApplicationStopCommand::~ApplicationStopCommand() {}

std::string ApplicationStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationStop";
}

int ApplicationStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}