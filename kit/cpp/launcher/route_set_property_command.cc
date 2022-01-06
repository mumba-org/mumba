// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_set_property_command.h"

std::unique_ptr<RouteSetPropertyCommand> RouteSetPropertyCommand::Create() {
  return std::make_unique<RouteSetPropertyCommand>();
}

RouteSetPropertyCommand::RouteSetPropertyCommand() {

}

RouteSetPropertyCommand::~RouteSetPropertyCommand() {

}

std::string RouteSetPropertyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteSetProperty";
}


int RouteSetPropertyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}