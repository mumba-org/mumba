// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_read_command.h"

std::unique_ptr<ScriptReadCommand> ScriptReadCommand::Create() {
  return std::make_unique<ScriptReadCommand>();
}

ScriptReadCommand::ScriptReadCommand() {

}

ScriptReadCommand::~ScriptReadCommand() {

}

std::string ScriptReadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptRead";
}


int ScriptReadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}