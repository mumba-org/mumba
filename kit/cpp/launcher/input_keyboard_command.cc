// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/input_keyboard_command.h"

std::unique_ptr<InputKeyboardCommand> InputKeyboardCommand::Create() {
  return std::make_unique<InputKeyboardCommand>();
}

InputKeyboardCommand::InputKeyboardCommand() {

}

InputKeyboardCommand::~InputKeyboardCommand() {

}

std::string InputKeyboardCommand::GetCommandMethod() const {
  return "/mumba.Mumba/InputKeyboard";
}


int InputKeyboardCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}