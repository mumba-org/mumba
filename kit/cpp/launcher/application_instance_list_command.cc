// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_instance_list_command.h"

std::unique_ptr<ApplicationInstanceListCommand> ApplicationInstanceListCommand::Create() {
  return std::make_unique<ApplicationInstanceListCommand>();
}

ApplicationInstanceListCommand::ApplicationInstanceListCommand() {

}
 
ApplicationInstanceListCommand::~ApplicationInstanceListCommand() {

}

std::string ApplicationInstanceListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationInstanceList";
}

int ApplicationInstanceListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}