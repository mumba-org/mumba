// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_remove_command.h"

std::unique_ptr<ScriptRemoveCommand> ScriptRemoveCommand::Create() {
  return std::make_unique<ScriptRemoveCommand>();
}

ScriptRemoveCommand::ScriptRemoveCommand() {

}

ScriptRemoveCommand::~ScriptRemoveCommand() {

}

std::string ScriptRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptRemove";
}


int ScriptRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}