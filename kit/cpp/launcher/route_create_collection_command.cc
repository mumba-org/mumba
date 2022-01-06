// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_create_collection_command.h"

std::unique_ptr<RouteCreateCollectionCommand> RouteCreateCollectionCommand::Create() {
  return std::make_unique<RouteCreateCollectionCommand>();
}

RouteCreateCollectionCommand::RouteCreateCollectionCommand() {

}

RouteCreateCollectionCommand::~RouteCreateCollectionCommand() {

}

std::string RouteCreateCollectionCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteCreateCollection";
}


int RouteCreateCollectionCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}