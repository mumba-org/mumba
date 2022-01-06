// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_unpin_command.h"

std::unique_ptr<ApplicationUnpinCommand> ApplicationUnpinCommand::Create() {
  return std::make_unique<ApplicationUnpinCommand>();
}

ApplicationUnpinCommand::ApplicationUnpinCommand() {

}

ApplicationUnpinCommand::~ApplicationUnpinCommand() {

}

std::string ApplicationUnpinCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationUnpin";
}

int ApplicationUnpinCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}