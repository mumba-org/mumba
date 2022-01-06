// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_run_command.h"

std::unique_ptr<ScriptRunCommand> ScriptRunCommand::Create() {
  return std::make_unique<ScriptRunCommand>();
}

ScriptRunCommand::ScriptRunCommand() {

}

ScriptRunCommand::~ScriptRunCommand() {

}

std::string ScriptRunCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptRun";
}


int ScriptRunCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}