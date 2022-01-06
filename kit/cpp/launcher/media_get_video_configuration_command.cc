// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/media_get_video_configuration_command.h"

std::unique_ptr<MediaGetVideoConfigurationCommand> MediaGetVideoConfigurationCommand::Create() {
  return std::make_unique<MediaGetVideoConfigurationCommand>();
}

MediaGetVideoConfigurationCommand::MediaGetVideoConfigurationCommand() {

}

MediaGetVideoConfigurationCommand::~MediaGetVideoConfigurationCommand() {

}

std::string MediaGetVideoConfigurationCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MediaGetVideoConfiguration";
}


int MediaGetVideoConfigurationCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}