// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/window_close_command.h"

std::unique_ptr<WindowCloseCommand> WindowCloseCommand::Create() {
  return std::make_unique<WindowCloseCommand>();
}

WindowCloseCommand::WindowCloseCommand() {

}

WindowCloseCommand::~WindowCloseCommand() {

}

std::string WindowCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WindowClose";
}


int WindowCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}