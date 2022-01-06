// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/remote_playback_watch_availability_command.h"

std::unique_ptr<RemotePlaybackWatchAvailabilityCommand> RemotePlaybackWatchAvailabilityCommand::Create() {
  return std::make_unique<RemotePlaybackWatchAvailabilityCommand>();
}

RemotePlaybackWatchAvailabilityCommand::RemotePlaybackWatchAvailabilityCommand() {

}

RemotePlaybackWatchAvailabilityCommand::~RemotePlaybackWatchAvailabilityCommand() {

}

std::string RemotePlaybackWatchAvailabilityCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RemotePlaybackWatchAvailability";
}


int RemotePlaybackWatchAvailabilityCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}