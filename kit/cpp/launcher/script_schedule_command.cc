// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/script_schedule_command.h"

std::unique_ptr<ScriptScheduleCommand> ScriptScheduleCommand::Create() {
  return std::make_unique<ScriptScheduleCommand>();
}

ScriptScheduleCommand::ScriptScheduleCommand() {

}

ScriptScheduleCommand::~ScriptScheduleCommand() {

}

std::string ScriptScheduleCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ScriptSchedule";
}


int ScriptScheduleCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}