// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/input_mouse_command.h"

std::unique_ptr<InputMouseCommand> InputMouseCommand::Create() {
  return std::make_unique<InputMouseCommand>();
}

InputMouseCommand::InputMouseCommand() {

}

InputMouseCommand::~InputMouseCommand() {

}

std::string InputMouseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/InputMouse";
}


int InputMouseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}