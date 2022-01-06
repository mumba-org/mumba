// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_get_entry_command.h"

std::unique_ptr<RouteGetEntryCommand> RouteGetEntryCommand::Create() {
  return std::make_unique<RouteGetEntryCommand>();
}

RouteGetEntryCommand::RouteGetEntryCommand() {

}

RouteGetEntryCommand::~RouteGetEntryCommand() {

}

std::string RouteGetEntryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteGetEntry";
}


int RouteGetEntryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}