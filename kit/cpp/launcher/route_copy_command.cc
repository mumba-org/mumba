// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_copy_command.h"

std::unique_ptr<RouteCopyCommand> RouteCopyCommand::Create() {
  return std::make_unique<RouteCopyCommand>();
}

RouteCopyCommand::RouteCopyCommand() {

}

RouteCopyCommand::~RouteCopyCommand() {

}

std::string RouteCopyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteCopy";
}


int RouteCopyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}