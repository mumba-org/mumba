// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_query_command.h"

std::unique_ptr<RouteQueryCommand> RouteQueryCommand::Create() {
  return std::make_unique<RouteQueryCommand>();
}

RouteQueryCommand::RouteQueryCommand() {

}

RouteQueryCommand::~RouteQueryCommand() {

}

std::string RouteQueryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteQuery";
}


int RouteQueryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}