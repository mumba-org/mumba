// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_set_entry_command.h"

std::unique_ptr<RouteSetEntryCommand> RouteSetEntryCommand::Create() {
  return std::make_unique<RouteSetEntryCommand>();
}

RouteSetEntryCommand::RouteSetEntryCommand() {

}

RouteSetEntryCommand::~RouteSetEntryCommand() {

}

std::string RouteSetEntryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteSetEntry";
}


int RouteSetEntryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}