// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_remove_entry_command.h"

std::unique_ptr<RouteRemoveEntryCommand> RouteRemoveEntryCommand::Create() {
  return std::make_unique<RouteRemoveEntryCommand>();
}

RouteRemoveEntryCommand::RouteRemoveEntryCommand() {

}

RouteRemoveEntryCommand::~RouteRemoveEntryCommand() {

}

std::string RouteRemoveEntryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteRemoveEntry";
}


int RouteRemoveEntryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}