// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_ambient_light_start_command.h"

std::unique_ptr<SensorAmbientLightStartCommand> SensorAmbientLightStartCommand::Create() {
  return std::make_unique<SensorAmbientLightStartCommand>();
}

SensorAmbientLightStartCommand::SensorAmbientLightStartCommand() {

}

SensorAmbientLightStartCommand::~SensorAmbientLightStartCommand() {

}

std::string SensorAmbientLightStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorAmbientLightStart";
}


int SensorAmbientLightStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}