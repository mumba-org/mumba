// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/usb_request_device_command.h"

std::unique_ptr<USBRequestDeviceCommand> USBRequestDeviceCommand::Create() {
  return std::make_unique<USBRequestDeviceCommand>();
}

USBRequestDeviceCommand::USBRequestDeviceCommand() {

}

USBRequestDeviceCommand::~USBRequestDeviceCommand() {

}

std::string USBRequestDeviceCommand::GetCommandMethod() const {
  return "/mumba.Mumba/USBRequestDevice";
}


int USBRequestDeviceCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}