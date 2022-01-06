// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/input_touch_command.h"

std::unique_ptr<InputTouchCommand> InputTouchCommand::Create() {
  return std::make_unique<InputTouchCommand>();
}

InputTouchCommand::InputTouchCommand() {

}

InputTouchCommand::~InputTouchCommand() {

}

std::string InputTouchCommand::GetCommandMethod() const {
  return "/mumba.Mumba/InputTouch";
}


int InputTouchCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}