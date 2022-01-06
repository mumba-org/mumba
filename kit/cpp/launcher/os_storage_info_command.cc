// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/os_storage_info_command.h"

std::unique_ptr<OSStorageInfoCommand> OSStorageInfoCommand::Create() {
  return std::make_unique<OSStorageInfoCommand>();
}

OSStorageInfoCommand::OSStorageInfoCommand() {

}

OSStorageInfoCommand::~OSStorageInfoCommand() {

}

std::string OSStorageInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/OSStorageInfo";
}


int OSStorageInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}