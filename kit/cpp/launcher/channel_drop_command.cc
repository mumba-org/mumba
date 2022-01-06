// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/channel_drop_command.h"

std::unique_ptr<ChannelDropCommand> ChannelDropCommand::Create() {
  return std::make_unique<ChannelDropCommand>();
}

ChannelDropCommand::ChannelDropCommand() {

}

ChannelDropCommand::~ChannelDropCommand() {

}

std::string ChannelDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ChannelDrop";
}


int ChannelDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}