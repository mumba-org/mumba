// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_move_to_command.h"

std::unique_ptr<DOMMoveToCommand> DOMMoveToCommand::Create() {
  return std::make_unique<DOMMoveToCommand>();
}

DOMMoveToCommand::DOMMoveToCommand() {

}

DOMMoveToCommand::~DOMMoveToCommand() {

}

std::string DOMMoveToCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMMoveTo";
}


int DOMMoveToCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}