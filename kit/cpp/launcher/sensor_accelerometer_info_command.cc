// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_accelerometer_info_command.h"

std::unique_ptr<SensorAccelerometerInfoCommand> SensorAccelerometerInfoCommand::Create() {
  return std::make_unique<SensorAccelerometerInfoCommand>();
}

SensorAccelerometerInfoCommand::SensorAccelerometerInfoCommand() {

}

SensorAccelerometerInfoCommand::~SensorAccelerometerInfoCommand() {

}

std::string SensorAccelerometerInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorAccelerometerInfo";
}


int SensorAccelerometerInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}