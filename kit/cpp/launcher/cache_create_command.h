// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_CACHE_CREATE_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_CACHE_CREATE_COMMAND_H_

#include "launcher/command.h"

class CacheCreateCommand : public Command {
public:
 static std::unique_ptr<CacheCreateCommand> Create();

 CacheCreateCommand();
 ~CacheCreateCommand() override;
 
 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
};

#endif