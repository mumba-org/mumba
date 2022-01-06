// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/screen_orientation_get_command.h"

std::unique_ptr<ScreenOrientationGetCommand> ScreenOrientationGetCommand::Create() {
  return std::make_unique<ScreenOrientationGetCommand>();
}

ScreenOrientationGetCommand::ScreenOrientationGetCommand() {

}

ScreenOrientationGetCommand::~ScreenOrientationGetCommand() {

}

std::string ScreenOrientationGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScreenOrientationGet";
}


int ScreenOrientationGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}