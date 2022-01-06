// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_resolve_command.h"

std::unique_ptr<RouteResolveCommand> RouteResolveCommand::Create() {
  return std::make_unique<RouteResolveCommand>();
}

RouteResolveCommand::RouteResolveCommand() {

}

RouteResolveCommand::~RouteResolveCommand() {

}

std::string RouteResolveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteResolve";
}


int RouteResolveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}