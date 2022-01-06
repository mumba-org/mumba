// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/session_list_command.h"

std::unique_ptr<SessionListCommand> SessionListCommand::Create() {
  return std::make_unique<SessionListCommand>();
}

SessionListCommand::SessionListCommand() {

}

SessionListCommand::~SessionListCommand() {

}

std::string SessionListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SessionList";
}


int SessionListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}