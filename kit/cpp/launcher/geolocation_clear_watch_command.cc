// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/geolocation_clear_watch_command.h"

std::unique_ptr<GeolocationClearWatchCommand> GeolocationClearWatchCommand::Create() {
  return std::make_unique<GeolocationClearWatchCommand>();
}

GeolocationClearWatchCommand::GeolocationClearWatchCommand() {

}

GeolocationClearWatchCommand::~GeolocationClearWatchCommand() {

}

std::string GeolocationClearWatchCommand::GetCommandMethod() const {
  return "/mumba.Mumba/GeolocationClearWatch";
}


int GeolocationClearWatchCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}