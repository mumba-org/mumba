// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_remove_collection_command.h"

std::unique_ptr<RouteRemoveCollectionCommand> RouteRemoveCollectionCommand::Create() {
  return std::make_unique<RouteRemoveCollectionCommand>();
}

RouteRemoveCollectionCommand::RouteRemoveCollectionCommand() {

}

RouteRemoveCollectionCommand::~RouteRemoveCollectionCommand() {

}

std::string RouteRemoveCollectionCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteRemoveCollection";
}


int RouteRemoveCollectionCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}