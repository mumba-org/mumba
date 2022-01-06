// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_module_list_command.h"

std::unique_ptr<ScriptModuleListCommand> ScriptModuleListCommand::Create() {
  return std::make_unique<ScriptModuleListCommand>();
}

ScriptModuleListCommand::ScriptModuleListCommand() {

}

ScriptModuleListCommand::~ScriptModuleListCommand() {

}

std::string ScriptModuleListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptModuleList";
}


int ScriptModuleListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}