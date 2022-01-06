// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/screen_get_keep_awake_command.h"

std::unique_ptr<ScreenGetKeepAwakeCommand> ScreenGetKeepAwakeCommand::Create() {
  return std::make_unique<ScreenGetKeepAwakeCommand>();
}

ScreenGetKeepAwakeCommand::ScreenGetKeepAwakeCommand() {

}

ScreenGetKeepAwakeCommand::~ScreenGetKeepAwakeCommand() {

}

std::string ScreenGetKeepAwakeCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScreenGetKeepAwake";
}


int ScreenGetKeepAwakeCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}