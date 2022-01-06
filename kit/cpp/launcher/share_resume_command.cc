// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_resume_command.h"

std::unique_ptr<ShareResumeCommand> ShareResumeCommand::Create() {
  return std::make_unique<ShareResumeCommand>();
}

ShareResumeCommand::ShareResumeCommand() {

}

ShareResumeCommand::~ShareResumeCommand() {

}

std::string ShareResumeCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareResume";
}


int ShareResumeCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}