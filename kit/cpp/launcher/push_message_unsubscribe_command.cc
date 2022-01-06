// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/push_message_unsubscribe_command.h"

std::unique_ptr<PushMessageUnsubscribeCommand> PushMessageUnsubscribeCommand::Create() {
  return std::make_unique<PushMessageUnsubscribeCommand>();
}

PushMessageUnsubscribeCommand::PushMessageUnsubscribeCommand() {

}

PushMessageUnsubscribeCommand::~PushMessageUnsubscribeCommand() {

}

std::string PushMessageUnsubscribeCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PushMessageUnsubscribe";
}


int PushMessageUnsubscribeCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}