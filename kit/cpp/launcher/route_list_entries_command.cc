// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_list_entries_command.h"

std::unique_ptr<RouteListEntriesCommand> RouteListEntriesCommand::Create() {
  return std::make_unique<RouteListEntriesCommand>();
}

RouteListEntriesCommand::RouteListEntriesCommand() {

}

RouteListEntriesCommand::~RouteListEntriesCommand() {

}

std::string RouteListEntriesCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteListEntries";
}


int RouteListEntriesCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}