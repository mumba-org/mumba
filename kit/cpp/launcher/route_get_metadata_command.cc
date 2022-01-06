// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/route_get_metadata_command.h"

std::unique_ptr<RouteGetMetadataCommand> RouteGetMetadataCommand::Create() {
  return std::make_unique<RouteGetMetadataCommand>();
}

RouteGetMetadataCommand::RouteGetMetadataCommand() {

}

RouteGetMetadataCommand::~RouteGetMetadataCommand() {

}

std::string RouteGetMetadataCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RouteGetMetadata";
}


int RouteGetMetadataCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}