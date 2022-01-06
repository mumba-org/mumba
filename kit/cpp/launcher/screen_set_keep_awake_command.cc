// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/screen_set_keep_awake_command.h"

std::unique_ptr<ScreenSetKeepAwakeCommand> ScreenSetKeepAwakeCommand::Create() {
  return std::make_unique<ScreenSetKeepAwakeCommand>();
}

ScreenSetKeepAwakeCommand::ScreenSetKeepAwakeCommand() {

}

ScreenSetKeepAwakeCommand::~ScreenSetKeepAwakeCommand() {

}

std::string ScreenSetKeepAwakeCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScreenSetKeepAwake";
}


int ScreenSetKeepAwakeCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}