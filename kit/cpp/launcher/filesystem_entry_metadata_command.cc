// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_entry_metadata_command.h"

std::unique_ptr<FilesystemEntryMetadataCommand> FilesystemEntryMetadataCommand::Create() {
  return std::make_unique<FilesystemEntryMetadataCommand>();
}

FilesystemEntryMetadataCommand::FilesystemEntryMetadataCommand() {

}

FilesystemEntryMetadataCommand::~FilesystemEntryMetadataCommand() {

}

std::string FilesystemEntryMetadataCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemEntryMetadata";
}


int FilesystemEntryMetadataCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}