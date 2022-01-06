// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_status_command.h"

std::unique_ptr<ApplicationStatusCommand> ApplicationStatusCommand::Create() {
  return std::make_unique<ApplicationStatusCommand>();
}

ApplicationStatusCommand::ApplicationStatusCommand() {}

ApplicationStatusCommand::~ApplicationStatusCommand() {}

std::string ApplicationStatusCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationStatus";
}

int ApplicationStatusCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}