// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/os_cpu_info_command.h"

std::unique_ptr<OSCpuInfoCommand> OSCpuInfoCommand::Create() {
  return std::make_unique<OSCpuInfoCommand>();
}

OSCpuInfoCommand::OSCpuInfoCommand() {

}

OSCpuInfoCommand::~OSCpuInfoCommand() {

}

std::string OSCpuInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/OSCpuInfo";
}


int OSCpuInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}