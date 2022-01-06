// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_copy_command.h"

std::unique_ptr<ShareCopyCommand> ShareCopyCommand::Create() {
  return std::make_unique<ShareCopyCommand>();
}

ShareCopyCommand::ShareCopyCommand() {

}

ShareCopyCommand::~ShareCopyCommand() {

}

std::string ShareCopyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareCopy";
}


int ShareCopyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}