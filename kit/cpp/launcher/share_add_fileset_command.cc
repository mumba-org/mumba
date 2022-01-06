// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_add_fileset_command.h"

std::unique_ptr<ShareAddFilesetCommand> ShareAddFilesetCommand::Create() {
  return std::make_unique<ShareAddFilesetCommand>();
}

ShareAddFilesetCommand::ShareAddFilesetCommand() {

}

ShareAddFilesetCommand::~ShareAddFilesetCommand() {

}

std::string ShareAddFilesetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareAddFileset";
}


int ShareAddFilesetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}