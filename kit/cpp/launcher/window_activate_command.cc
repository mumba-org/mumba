// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/window_activate_command.h"

std::unique_ptr<WindowActivateCommand> WindowActivateCommand::Create() {
  return std::make_unique<WindowActivateCommand>();
}

WindowActivateCommand::WindowActivateCommand() {

}

WindowActivateCommand::~WindowActivateCommand() {

}

std::string WindowActivateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WindowActivate";
}


int WindowActivateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}