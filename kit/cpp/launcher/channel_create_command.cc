// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/channel_create_command.h"

std::unique_ptr<ChannelCreateCommand> ChannelCreateCommand::Create() {
  return std::make_unique<ChannelCreateCommand>();
}

ChannelCreateCommand::ChannelCreateCommand() {

}

ChannelCreateCommand::~ChannelCreateCommand() {

}

std::string ChannelCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ChannelCreate";
}


int ChannelCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}