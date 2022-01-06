// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_entry_copy_command.h"

std::unique_ptr<FilesystemEntryCopyCommand> FilesystemEntryCopyCommand::Create() {
  return std::make_unique<FilesystemEntryCopyCommand>();
}

FilesystemEntryCopyCommand::FilesystemEntryCopyCommand() {

}

FilesystemEntryCopyCommand::~FilesystemEntryCopyCommand() {

}

std::string FilesystemEntryCopyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemEntryCopy";
}


int FilesystemEntryCopyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}