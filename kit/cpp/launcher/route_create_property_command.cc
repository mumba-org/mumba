// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_create_property_command.h"

std::unique_ptr<RouteCreatePropertyCommand> RouteCreatePropertyCommand::Create() {
  return std::make_unique<RouteCreatePropertyCommand>();
}

RouteCreatePropertyCommand::RouteCreatePropertyCommand() {

}

RouteCreatePropertyCommand::~RouteCreatePropertyCommand() {

}

std::string RouteCreatePropertyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteCreateProperty";
}


int RouteCreatePropertyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}