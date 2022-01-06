// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_write_command.h"

std::unique_ptr<ShareWriteCommand> ShareWriteCommand::Create() {
  return std::make_unique<ShareWriteCommand>();
}

ShareWriteCommand::ShareWriteCommand() {

}

ShareWriteCommand::~ShareWriteCommand() {

}

std::string ShareWriteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareWrite";
}


int ShareWriteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}