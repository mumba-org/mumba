// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/screen_orientation_lock_command.h"

std::unique_ptr<ScreenOrientationLockCommand> ScreenOrientationLockCommand::Create() {
  return std::make_unique<ScreenOrientationLockCommand>();
}

ScreenOrientationLockCommand::ScreenOrientationLockCommand() {

}

ScreenOrientationLockCommand::~ScreenOrientationLockCommand() {

}

std::string ScreenOrientationLockCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScreenOrientationLock";
}


int ScreenOrientationLockCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}