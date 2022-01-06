// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/push_message_subscribe_command.h"

std::unique_ptr<PushMessageSubscribeCommand> PushMessageSubscribeCommand::Create() {
  return std::make_unique<PushMessageSubscribeCommand>();
}

PushMessageSubscribeCommand::PushMessageSubscribeCommand() {

}

PushMessageSubscribeCommand::~PushMessageSubscribeCommand() {

}

std::string PushMessageSubscribeCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PushMessageSubscribe";
}


int PushMessageSubscribeCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}