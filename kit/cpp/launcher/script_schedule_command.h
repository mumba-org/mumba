// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_SCRIPT_SCHEDULE_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_SCRIPT_SCHEDULE_COMMAND_H_

#include "launcher/command.h"

class ScriptScheduleCommand : public Command {
public:
 static std::unique_ptr<ScriptScheduleCommand> Create();

 ScriptScheduleCommand();
 ~ScriptScheduleCommand() override;
 
 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
};

#endif