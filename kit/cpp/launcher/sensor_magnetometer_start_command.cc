// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_magnetometer_start_command.h"

std::unique_ptr<SensorMagnetometerStartCommand> SensorMagnetometerStartCommand::Create() {
  return std::make_unique<SensorMagnetometerStartCommand>();
}

SensorMagnetometerStartCommand::SensorMagnetometerStartCommand() {

}

SensorMagnetometerStartCommand::~SensorMagnetometerStartCommand() {

}

std::string SensorMagnetometerStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorMagnetometerStart";
}


int SensorMagnetometerStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}