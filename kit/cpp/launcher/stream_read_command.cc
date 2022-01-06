// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/stream_read_command.h"

std::unique_ptr<StreamReadCommand> StreamReadCommand::Create() {
  return std::make_unique<StreamReadCommand>();
}

StreamReadCommand::StreamReadCommand() {

}

StreamReadCommand::~StreamReadCommand() {

}

std::string StreamReadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/StreamRead";
}


int StreamReadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}