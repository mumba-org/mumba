// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_create_fileset_command.h"

std::unique_ptr<ShareCreateFilesetCommand> ShareCreateFilesetCommand::Create() {
  return std::make_unique<ShareCreateFilesetCommand>();
}

ShareCreateFilesetCommand::ShareCreateFilesetCommand() {

}

ShareCreateFilesetCommand::~ShareCreateFilesetCommand() {

}

std::string ShareCreateFilesetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareCreateFileset";
}


int ShareCreateFilesetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}