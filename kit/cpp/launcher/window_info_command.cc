// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/window_info_command.h"

std::unique_ptr<WindowInfoCommand> WindowInfoCommand::Create() {
  return std::make_unique<WindowInfoCommand>();
}

WindowInfoCommand::WindowInfoCommand() {

}

WindowInfoCommand::~WindowInfoCommand() {

}

std::string WindowInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WindowInfo";
}


int WindowInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}