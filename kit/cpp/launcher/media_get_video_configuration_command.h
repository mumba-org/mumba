// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_MEDIA_GET_VIDEO_CONFIGURATION_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_MEDIA_GET_VIDEO_CONFIGURATION_COMMAND_H_

#include "launcher/command.h"

class MediaGetVideoConfigurationCommand : public Command {
public:
 static std::unique_ptr<MediaGetVideoConfigurationCommand> Create();

 MediaGetVideoConfigurationCommand();
 ~MediaGetVideoConfigurationCommand() override;
 
 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
};

#endif