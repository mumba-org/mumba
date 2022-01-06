// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/filesystem_info_command.h"

std::unique_ptr<FilesystemInfoCommand> FilesystemInfoCommand::Create() {
  return std::make_unique<FilesystemInfoCommand>();
}

FilesystemInfoCommand::FilesystemInfoCommand() {

}

FilesystemInfoCommand::~FilesystemInfoCommand() {

}

std::string FilesystemInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FilesystemInfo";
}


int FilesystemInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}