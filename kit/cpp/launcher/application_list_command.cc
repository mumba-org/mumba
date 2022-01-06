// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_list_command.h"

std::unique_ptr<ApplicationListCommand> ApplicationListCommand::Create() {
  return std::make_unique<ApplicationListCommand>();
}

ApplicationListCommand::ApplicationListCommand() {

}
 
ApplicationListCommand::~ApplicationListCommand() {

}

std::string ApplicationListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationList";
}

int ApplicationListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}