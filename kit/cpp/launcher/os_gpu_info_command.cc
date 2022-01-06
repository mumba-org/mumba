// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/os_gpu_info_command.h"

std::unique_ptr<OSGpuInfoCommand> OSGpuInfoCommand::Create() {
  return std::make_unique<OSGpuInfoCommand>();
}

OSGpuInfoCommand::OSGpuInfoCommand() {

}

OSGpuInfoCommand::~OSGpuInfoCommand() {

}

std::string OSGpuInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/OSGpuInfo";
}


int OSGpuInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}