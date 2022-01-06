// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_directory_remove_command.h"

std::unique_ptr<FilesystemDirectoryRemoveCommand> FilesystemDirectoryRemoveCommand::Create() {
  return std::make_unique<FilesystemDirectoryRemoveCommand>();
}

FilesystemDirectoryRemoveCommand::FilesystemDirectoryRemoveCommand() {

}

FilesystemDirectoryRemoveCommand::~FilesystemDirectoryRemoveCommand() {

}

std::string FilesystemDirectoryRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemDirectoryRemove";
}


int FilesystemDirectoryRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}