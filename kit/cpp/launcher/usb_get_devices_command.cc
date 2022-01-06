// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/usb_get_devices_command.h"

std::unique_ptr<USBGetDevicesCommand> USBGetDevicesCommand::Create() {
  return std::make_unique<USBGetDevicesCommand>();
}

USBGetDevicesCommand::USBGetDevicesCommand() {

}

USBGetDevicesCommand::~USBGetDevicesCommand() {

}

std::string USBGetDevicesCommand::GetCommandMethod() const {
  return "/mumba.Mumba/USBGetDevices";
}


int USBGetDevicesCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}