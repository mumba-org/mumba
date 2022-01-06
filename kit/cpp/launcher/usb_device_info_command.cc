// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/usb_device_info_command.h"

std::unique_ptr<USBDeviceInfoCommand> USBDeviceInfoCommand::Create() {
  return std::make_unique<USBDeviceInfoCommand>();
}

USBDeviceInfoCommand::USBDeviceInfoCommand() {

}

USBDeviceInfoCommand::~USBDeviceInfoCommand() {

}

std::string USBDeviceInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/USBDeviceInfo";
}


int USBDeviceInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}