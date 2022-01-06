// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_create_entry_command.h"

std::unique_ptr<RouteCreateEntryCommand> RouteCreateEntryCommand::Create() {
  return std::make_unique<RouteCreateEntryCommand>();
}

RouteCreateEntryCommand::RouteCreateEntryCommand() {

}

RouteCreateEntryCommand::~RouteCreateEntryCommand() {

}

std::string RouteCreateEntryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteCreateEntry";
}


int RouteCreateEntryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}