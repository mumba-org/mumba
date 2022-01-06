// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/media_get_audio_configuration_command.h"

std::unique_ptr<MediaGetAudioConfigurationCommand> MediaGetAudioConfigurationCommand::Create() {
  return std::make_unique<MediaGetAudioConfigurationCommand>();
}

MediaGetAudioConfigurationCommand::MediaGetAudioConfigurationCommand() {

}

MediaGetAudioConfigurationCommand::~MediaGetAudioConfigurationCommand() {

}

std::string MediaGetAudioConfigurationCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MediaGetAudioConfiguration";
}


int MediaGetAudioConfigurationCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}