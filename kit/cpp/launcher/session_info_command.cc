// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/session_info_command.h"

std::unique_ptr<SessionInfoCommand> SessionInfoCommand::Create() {
  return std::make_unique<SessionInfoCommand>();
}

SessionInfoCommand::SessionInfoCommand() {

}

SessionInfoCommand::~SessionInfoCommand() {

}

std::string SessionInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SessionInfo";
}


int SessionInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}