// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/stream_list_command.h"

std::unique_ptr<StreamListCommand> StreamListCommand::Create() {
  return std::make_unique<StreamListCommand>();
}

StreamListCommand::StreamListCommand() {

}

StreamListCommand::~StreamListCommand() {

}

std::string StreamListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/StreamList";
}


int StreamListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}