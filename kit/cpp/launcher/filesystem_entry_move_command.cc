// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_entry_move_command.h"

std::unique_ptr<FilesystemEntryMoveCommand> FilesystemEntryMoveCommand::Create() {
  return std::make_unique<FilesystemEntryMoveCommand>();
}

FilesystemEntryMoveCommand::FilesystemEntryMoveCommand() {

}

FilesystemEntryMoveCommand::~FilesystemEntryMoveCommand() {

}

std::string FilesystemEntryMoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemEntryMove";
}


int FilesystemEntryMoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}