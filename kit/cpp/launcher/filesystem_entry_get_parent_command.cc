// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_entry_get_parent_command.h"

std::unique_ptr<FilesystemEntryGetParentCommand> FilesystemEntryGetParentCommand::Create() {
  return std::make_unique<FilesystemEntryGetParentCommand>();
}

FilesystemEntryGetParentCommand::FilesystemEntryGetParentCommand() {

}

FilesystemEntryGetParentCommand::~FilesystemEntryGetParentCommand() {

}

std::string FilesystemEntryGetParentCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemEntryGetParent";
}


int FilesystemEntryGetParentCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}