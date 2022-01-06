// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_orientation_info_command.h"

std::unique_ptr<SensorOrientationInfoCommand> SensorOrientationInfoCommand::Create() {
  return std::make_unique<SensorOrientationInfoCommand>();
}

SensorOrientationInfoCommand::SensorOrientationInfoCommand() {

}

SensorOrientationInfoCommand::~SensorOrientationInfoCommand() {

}

std::string SensorOrientationInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorOrientationInfo";
}


int SensorOrientationInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}