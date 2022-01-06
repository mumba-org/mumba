// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_list_collections_command.h"

std::unique_ptr<RouteListCollectionsCommand> RouteListCollectionsCommand::Create() {
  return std::make_unique<RouteListCollectionsCommand>();
}

RouteListCollectionsCommand::RouteListCollectionsCommand() {

}

RouteListCollectionsCommand::~RouteListCollectionsCommand() {

}

std::string RouteListCollectionsCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteListCollections";
}


int RouteListCollectionsCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}