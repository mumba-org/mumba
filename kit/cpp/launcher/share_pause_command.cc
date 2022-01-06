// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_pause_command.h"

std::unique_ptr<SharePauseCommand> SharePauseCommand::Create() {
  return std::make_unique<SharePauseCommand>();
}

SharePauseCommand::SharePauseCommand() {

}

SharePauseCommand::~SharePauseCommand() {

}

std::string SharePauseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SharePause";
}


int SharePauseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}