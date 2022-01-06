// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_accelerometer_start_command.h"

std::unique_ptr<SensorAccelerometerStartCommand> SensorAccelerometerStartCommand::Create() {
  return std::make_unique<SensorAccelerometerStartCommand>();
}

SensorAccelerometerStartCommand::SensorAccelerometerStartCommand() {

}

SensorAccelerometerStartCommand::~SensorAccelerometerStartCommand() {

}

std::string SensorAccelerometerStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorAccelerometerStart";
}


int SensorAccelerometerStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}