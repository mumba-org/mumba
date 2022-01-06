// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/keyboard_unlock_command.h"

std::unique_ptr<KeyboardUnlockCommand> KeyboardUnlockCommand::Create() {
  return std::make_unique<KeyboardUnlockCommand>();
}

KeyboardUnlockCommand::KeyboardUnlockCommand() {

}

KeyboardUnlockCommand::~KeyboardUnlockCommand() {

}

std::string KeyboardUnlockCommand::GetCommandMethod() const {
  return "/mumba.Mumba/KeyboardUnlock";
}


int KeyboardUnlockCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}