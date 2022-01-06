// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/drop_update_command.h"

std::unique_ptr<DropUpdateCommand> DropUpdateCommand::Create() {
  return std::make_unique<DropUpdateCommand>();
}

DropUpdateCommand::DropUpdateCommand() {}

DropUpdateCommand::~DropUpdateCommand() {}

std::string DropUpdateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DropUpdate";
}

int DropUpdateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}