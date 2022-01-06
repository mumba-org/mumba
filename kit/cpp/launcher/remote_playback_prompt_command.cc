// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/remote_playback_prompt_command.h"

std::unique_ptr<RemotePlaybackPromptCommand> RemotePlaybackPromptCommand::Create() {
  return std::make_unique<RemotePlaybackPromptCommand>();
}

RemotePlaybackPromptCommand::RemotePlaybackPromptCommand() {

}

RemotePlaybackPromptCommand::~RemotePlaybackPromptCommand() {

}

std::string RemotePlaybackPromptCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RemotePlaybackPrompt";
}


int RemotePlaybackPromptCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}