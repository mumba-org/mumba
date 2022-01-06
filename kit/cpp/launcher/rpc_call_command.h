// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_RPC_CALL_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_RPC_CALL_COMMAND_H_

#include "launcher/command.h"

/*
 * Call a rpc method by its name passing args
 * this is the fallthrough once no pre-defined command is found
 */
class RPCCallCommand : public Command {
public:
 static std::unique_ptr<RPCCallCommand> Create();
 
 RPCCallCommand();
 ~RPCCallCommand() override;

 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
};

#endif