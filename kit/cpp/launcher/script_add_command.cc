// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_add_command.h"

std::unique_ptr<ScriptAddCommand> ScriptAddCommand::Create() {
  return std::make_unique<ScriptAddCommand>();
}

ScriptAddCommand::ScriptAddCommand() {

}

ScriptAddCommand::~ScriptAddCommand() {

}

std::string ScriptAddCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptAdd";
}


int ScriptAddCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}