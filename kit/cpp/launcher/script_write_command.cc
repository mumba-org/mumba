// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_write_command.h"

std::unique_ptr<ScriptWriteCommand> ScriptWriteCommand::Create() {
  return std::make_unique<ScriptWriteCommand>();
}

ScriptWriteCommand::ScriptWriteCommand() {

}

ScriptWriteCommand::~ScriptWriteCommand() {

}

std::string ScriptWriteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptWrite";
}


int ScriptWriteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}