// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_magnetometer_stop_command.h"

std::unique_ptr<SensorMagnetometerStopCommand> SensorMagnetometerStopCommand::Create() {
  return std::make_unique<SensorMagnetometerStopCommand>();
}

SensorMagnetometerStopCommand::SensorMagnetometerStopCommand() {

}

SensorMagnetometerStopCommand::~SensorMagnetometerStopCommand() {

}

std::string SensorMagnetometerStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorMagnetometerStop";
}


int SensorMagnetometerStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}