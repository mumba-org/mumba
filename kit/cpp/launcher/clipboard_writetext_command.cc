// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/clipboard_writetext_command.h"

std::unique_ptr<ClipboardWriteTextCommand> ClipboardWriteTextCommand::Create() {
  return std::make_unique<ClipboardWriteTextCommand>();
}

ClipboardWriteTextCommand::ClipboardWriteTextCommand() {

}

ClipboardWriteTextCommand::~ClipboardWriteTextCommand() {

}

std::string ClipboardWriteTextCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ClipboardWriteText";
}


int ClipboardWriteTextCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}