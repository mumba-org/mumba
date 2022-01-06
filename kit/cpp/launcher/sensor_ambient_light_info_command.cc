// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_ambient_light_info_command.h"

std::unique_ptr<SensorAmbientLightInfoCommand> SensorAmbientLightInfoCommand::Create() {
  return std::make_unique<SensorAmbientLightInfoCommand>();
}

SensorAmbientLightInfoCommand::SensorAmbientLightInfoCommand() {

}

SensorAmbientLightInfoCommand::~SensorAmbientLightInfoCommand() {

}

std::string SensorAmbientLightInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorAmbientLightInfo";
}


int SensorAmbientLightInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}