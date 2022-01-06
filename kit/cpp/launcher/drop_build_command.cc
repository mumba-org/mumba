// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/drop_build_command.h"

std::unique_ptr<DropBuildCommand> DropBuildCommand::Create() {
  return std::make_unique<DropBuildCommand>();
}

DropBuildCommand::DropBuildCommand() {

}
 
DropBuildCommand::~DropBuildCommand() {

}

std::string DropBuildCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DropBuild";
}

int DropBuildCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}