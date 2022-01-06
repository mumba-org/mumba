// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_list_command.h"

std::unique_ptr<ScriptListCommand> ScriptListCommand::Create() {
  return std::make_unique<ScriptListCommand>();
}

ScriptListCommand::ScriptListCommand() {

}

ScriptListCommand::~ScriptListCommand() {

}

std::string ScriptListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptList";
}


int ScriptListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}