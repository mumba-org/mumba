// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/geolocation_get_current_position_command.h"

std::unique_ptr<GeolocationGetCurrentPositionCommand> GeolocationGetCurrentPositionCommand::Create() {
  return std::make_unique<GeolocationGetCurrentPositionCommand>();
}

GeolocationGetCurrentPositionCommand::GeolocationGetCurrentPositionCommand() {

}

GeolocationGetCurrentPositionCommand::~GeolocationGetCurrentPositionCommand() {

}

std::string GeolocationGetCurrentPositionCommand::GetCommandMethod() const {
  return "/mumba.Mumba/GeolocationGetCurrentPosition";
}


int GeolocationGetCurrentPositionCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}