// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_list_properties_command.h"

std::unique_ptr<RouteListPropertiesCommand> RouteListPropertiesCommand::Create() {
  return std::make_unique<RouteListPropertiesCommand>();
}

RouteListPropertiesCommand::RouteListPropertiesCommand() {

}

RouteListPropertiesCommand::~RouteListPropertiesCommand() {

}

std::string RouteListPropertiesCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteListProperties";
}


int RouteListPropertiesCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}