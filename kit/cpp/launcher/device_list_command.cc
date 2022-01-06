// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/device_list_command.h"

std::unique_ptr<DeviceListCommand> DeviceListCommand::Create() {
  return std::make_unique<DeviceListCommand>();
}

DeviceListCommand::DeviceListCommand() {

}

DeviceListCommand::~DeviceListCommand() {

}

std::string DeviceListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DeviceList";
}


int DeviceListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}