// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/remote_playback_cancel_watch_availability_command.h"

std::unique_ptr<RemotePlaybackCancelWatchAvailabilityCommand> RemotePlaybackCancelWatchAvailabilityCommand::Create() {
  return std::make_unique<RemotePlaybackCancelWatchAvailabilityCommand>();
}

RemotePlaybackCancelWatchAvailabilityCommand::RemotePlaybackCancelWatchAvailabilityCommand() {

}

RemotePlaybackCancelWatchAvailabilityCommand::~RemotePlaybackCancelWatchAvailabilityCommand() {

}

std::string RemotePlaybackCancelWatchAvailabilityCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RemotePlaybackCancelWatchAvailability";
}


int RemotePlaybackCancelWatchAvailabilityCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}