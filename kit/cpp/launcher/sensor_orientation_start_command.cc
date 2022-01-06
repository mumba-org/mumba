// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_orientation_start_command.h"

std::unique_ptr<SensorOrientationStartCommand> SensorOrientationStartCommand::Create() {
  return std::make_unique<SensorOrientationStartCommand>();
}

SensorOrientationStartCommand::SensorOrientationStartCommand() {

}

SensorOrientationStartCommand::~SensorOrientationStartCommand() {

}

std::string SensorOrientationStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorOrientationStart";
}


int SensorOrientationStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}