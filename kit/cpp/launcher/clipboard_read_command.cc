// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/clipboard_read_command.h"

std::unique_ptr<ClipboardReadCommand> ClipboardReadCommand::Create() {
  return std::make_unique<ClipboardReadCommand>();
}

ClipboardReadCommand::ClipboardReadCommand() {

}

ClipboardReadCommand::~ClipboardReadCommand() {

}

std::string ClipboardReadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ClipboardRead";
}


int ClipboardReadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}