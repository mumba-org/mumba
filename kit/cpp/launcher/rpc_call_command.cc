// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/rpc_call_command.h"

std::unique_ptr<RPCCallCommand> RPCCallCommand::Create() {
  return std::make_unique<RPCCallCommand>();
}

RPCCallCommand::RPCCallCommand() {

}

RPCCallCommand::~RPCCallCommand() {

}

std::string RPCCallCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RPCCall";
}

int RPCCallCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}