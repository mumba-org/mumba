// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_directory_get_file_command.h"

std::unique_ptr<FilesystemDirectoryGetFileCommand> FilesystemDirectoryGetFileCommand::Create() {
  return std::make_unique<FilesystemDirectoryGetFileCommand>();
}

FilesystemDirectoryGetFileCommand::FilesystemDirectoryGetFileCommand() {

}

FilesystemDirectoryGetFileCommand::~FilesystemDirectoryGetFileCommand() {

}

std::string FilesystemDirectoryGetFileCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemDirectoryGetFile";
}


int FilesystemDirectoryGetFileCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}