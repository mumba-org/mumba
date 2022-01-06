// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_directory_list_command.h"

std::unique_ptr<FilesystemDirectoryListCommand> FilesystemDirectoryListCommand::Create() {
  return std::make_unique<FilesystemDirectoryListCommand>();
}

FilesystemDirectoryListCommand::FilesystemDirectoryListCommand() {

}

FilesystemDirectoryListCommand::~FilesystemDirectoryListCommand() {

}

std::string FilesystemDirectoryListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemDirectoryList";
}


int FilesystemDirectoryListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}