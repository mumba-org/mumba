// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/stream_write_command.h"

std::unique_ptr<StreamWriteCommand> StreamWriteCommand::Create() {
  return std::make_unique<StreamWriteCommand>();
}

StreamWriteCommand::StreamWriteCommand() {

}

StreamWriteCommand::~StreamWriteCommand() {

}

std::string StreamWriteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/StreamWrite";
}


int StreamWriteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}