// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/os_memory_info_command.h"

std::unique_ptr<OSMemoryInfoCommand> OSMemoryInfoCommand::Create() {
  return std::make_unique<OSMemoryInfoCommand>();
}

OSMemoryInfoCommand::OSMemoryInfoCommand() {

}

OSMemoryInfoCommand::~OSMemoryInfoCommand() {

}

std::string OSMemoryInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/OSMemoryInfo";
}


int OSMemoryInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}