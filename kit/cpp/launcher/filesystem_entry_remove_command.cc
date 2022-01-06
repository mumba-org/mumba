// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_entry_remove_command.h"

std::unique_ptr<FilesystemEntryRemoveCommand> FilesystemEntryRemoveCommand::Create() {
  return std::make_unique<FilesystemEntryRemoveCommand>();
}

FilesystemEntryRemoveCommand::FilesystemEntryRemoveCommand() {

}

FilesystemEntryRemoveCommand::~FilesystemEntryRemoveCommand() {

}

std::string FilesystemEntryRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemEntryRemove";
}


int FilesystemEntryRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}