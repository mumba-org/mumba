// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/battery_info_command.h"

std::unique_ptr<BatteryInfoCommand> BatteryInfoCommand::Create() {
  return std::make_unique<BatteryInfoCommand>();
}

BatteryInfoCommand::BatteryInfoCommand() {

}

BatteryInfoCommand::~BatteryInfoCommand() {

}

std::string BatteryInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BatteryGetInfo";
}

int BatteryInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}