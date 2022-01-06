// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/geolocation_watch_position_command.h"

std::unique_ptr<GeolocationWatchPositionCommand> GeolocationWatchPositionCommand::Create() {
  return std::make_unique<GeolocationWatchPositionCommand>();
}

GeolocationWatchPositionCommand::GeolocationWatchPositionCommand() {

}

GeolocationWatchPositionCommand::~GeolocationWatchPositionCommand() {

}

std::string GeolocationWatchPositionCommand::GetCommandMethod() const {
  return "/mumba.Mumba/GeolocationWatchPosition";
}


int GeolocationWatchPositionCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}