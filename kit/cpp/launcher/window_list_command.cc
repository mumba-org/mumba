// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/window_list_command.h"

std::unique_ptr<WindowListCommand> WindowListCommand::Create() {
  return std::make_unique<WindowListCommand>();
}

WindowListCommand::WindowListCommand() {

}

WindowListCommand::~WindowListCommand() {

}

std::string WindowListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WindowList";
}


int WindowListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}