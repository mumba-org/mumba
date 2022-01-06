// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/clipboard_readtext_command.h"

std::unique_ptr<ClipboardReadTextCommand> ClipboardReadTextCommand::Create() {
  return std::make_unique<ClipboardReadTextCommand>();
}

ClipboardReadTextCommand::ClipboardReadTextCommand() {

}

ClipboardReadTextCommand::~ClipboardReadTextCommand() {

}

std::string ClipboardReadTextCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ClipboardReadText";
}


int ClipboardReadTextCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}