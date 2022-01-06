// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_ambient_light_stop_command.h"

std::unique_ptr<SensorAmbientLightStopCommand> SensorAmbientLightStopCommand::Create() {
  return std::make_unique<SensorAmbientLightStopCommand>();
}

SensorAmbientLightStopCommand::SensorAmbientLightStopCommand() {

}

SensorAmbientLightStopCommand::~SensorAmbientLightStopCommand() {

}

std::string SensorAmbientLightStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorAmbientLightStop";
}


int SensorAmbientLightStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}