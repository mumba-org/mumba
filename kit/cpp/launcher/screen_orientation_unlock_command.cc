// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/screen_orientation_unlock_command.h"

std::unique_ptr<ScreenOrientationUnlockCommand> ScreenOrientationUnlockCommand::Create() {
  return std::make_unique<ScreenOrientationUnlockCommand>();
}

ScreenOrientationUnlockCommand::ScreenOrientationUnlockCommand() {

}

ScreenOrientationUnlockCommand::~ScreenOrientationUnlockCommand() {

}

std::string ScreenOrientationUnlockCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScreenOrientationUnlock";
}


int ScreenOrientationUnlockCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}