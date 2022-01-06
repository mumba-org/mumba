// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/drop_init_command.h"

std::unique_ptr<DropInitCommand> DropInitCommand::Create() {
  return std::make_unique<DropInitCommand>();
}

DropInitCommand::DropInitCommand() {

}
 
DropInitCommand::~DropInitCommand() {

}

std::string DropInitCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DropInit";
}

int DropInitCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}