// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_remove_property_command.h"

std::unique_ptr<RouteRemovePropertyCommand> RouteRemovePropertyCommand::Create() {
  return std::make_unique<RouteRemovePropertyCommand>();
}

RouteRemovePropertyCommand::RouteRemovePropertyCommand() {

}

RouteRemovePropertyCommand::~RouteRemovePropertyCommand() {

}

std::string RouteRemovePropertyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteRemoveProperty";
}


int RouteRemovePropertyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}