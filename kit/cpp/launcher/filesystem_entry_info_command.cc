// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_entry_info_command.h"

std::unique_ptr<FilesystemEntryInfoCommand> FilesystemEntryInfoCommand::Create() {
  return std::make_unique<FilesystemEntryInfoCommand>();
}

FilesystemEntryInfoCommand::FilesystemEntryInfoCommand() {

}

FilesystemEntryInfoCommand::~FilesystemEntryInfoCommand() {

}

std::string FilesystemEntryInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemEntryInfo";
}


int FilesystemEntryInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}