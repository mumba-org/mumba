// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_SHARE_KVDB_GET_ALL_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_SHARE_KVDB_GET_ALL_COMMAND_H_

#include "launcher/command.h"

class ShareKvDbGetAllCommand : public Command {
public:
 static std::unique_ptr<ShareKvDbGetAllCommand> Create();

 ShareKvDbGetAllCommand();
 ~ShareKvDbGetAllCommand() override;
 
 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
};

#endif