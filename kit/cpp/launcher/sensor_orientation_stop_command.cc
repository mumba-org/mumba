// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_orientation_stop_command.h"

std::unique_ptr<SensorOrientationStopCommand> SensorOrientationStopCommand::Create() {
  return std::make_unique<SensorOrientationStopCommand>();
}

SensorOrientationStopCommand::SensorOrientationStopCommand() {

}

SensorOrientationStopCommand::~SensorOrientationStopCommand() {

}

std::string SensorOrientationStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorOrientationStop";
}


int SensorOrientationStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}