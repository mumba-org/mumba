// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/clipboard_write_command.h"

std::unique_ptr<ClipboardWriteCommand> ClipboardWriteCommand::Create() {
  return std::make_unique<ClipboardWriteCommand>();
}

ClipboardWriteCommand::ClipboardWriteCommand() {

}

ClipboardWriteCommand::~ClipboardWriteCommand() {

}

std::string ClipboardWriteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ClipboardWrite";
}


int ClipboardWriteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}