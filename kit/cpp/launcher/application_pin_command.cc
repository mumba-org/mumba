// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_pin_command.h"

std::unique_ptr<ApplicationPinCommand> ApplicationPinCommand::Create() {
  return std::make_unique<ApplicationPinCommand>();
}

ApplicationPinCommand::ApplicationPinCommand() {

}

ApplicationPinCommand::~ApplicationPinCommand() {

}

std::string ApplicationPinCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationPin";
}


int ApplicationPinCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}