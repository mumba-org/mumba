// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/keyboard_lock_command.h"

std::unique_ptr<KeyboardLockCommand> KeyboardLockCommand::Create() {
  return std::make_unique<KeyboardLockCommand>();
}

KeyboardLockCommand::KeyboardLockCommand() {

}

KeyboardLockCommand::~KeyboardLockCommand() {

}

std::string KeyboardLockCommand::GetCommandMethod() const {
  return "/mumba.Mumba/KeyboardLock";
}


int KeyboardLockCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}