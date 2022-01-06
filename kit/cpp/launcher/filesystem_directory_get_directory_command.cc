// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_directory_get_directory_command.h"

std::unique_ptr<FilesystemDirectoryGetDirectoryCommand> FilesystemDirectoryGetDirectoryCommand::Create() {
  return std::make_unique<FilesystemDirectoryGetDirectoryCommand>();
}

FilesystemDirectoryGetDirectoryCommand::FilesystemDirectoryGetDirectoryCommand() {

}

FilesystemDirectoryGetDirectoryCommand::~FilesystemDirectoryGetDirectoryCommand() {

}

std::string FilesystemDirectoryGetDirectoryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemDirectoryGetDirectory";
}


int FilesystemDirectoryGetDirectoryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}