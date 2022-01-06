// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_magnetometer_info_command.h"

std::unique_ptr<SensorMagnetometerInfoCommand> SensorMagnetometerInfoCommand::Create() {
  return std::make_unique<SensorMagnetometerInfoCommand>();
}

SensorMagnetometerInfoCommand::SensorMagnetometerInfoCommand() {

}

SensorMagnetometerInfoCommand::~SensorMagnetometerInfoCommand() {

}

std::string SensorMagnetometerInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorMagnetometerInfo";
}


int SensorMagnetometerInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}