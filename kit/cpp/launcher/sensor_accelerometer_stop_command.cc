// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_accelerometer_stop_command.h"

std::unique_ptr<SensorAccelerometerStopCommand> SensorAccelerometerStopCommand::Create() {
  return std::make_unique<SensorAccelerometerStopCommand>();
}

SensorAccelerometerStopCommand::SensorAccelerometerStopCommand() {

}

SensorAccelerometerStopCommand::~SensorAccelerometerStopCommand() {

}

std::string SensorAccelerometerStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorAccelerometerStop";
}


int SensorAccelerometerStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}