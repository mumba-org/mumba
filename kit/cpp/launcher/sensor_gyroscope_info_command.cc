// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_gyroscope_info_command.h"

std::unique_ptr<SensorGyroscopeInfoCommand> SensorGyroscopeInfoCommand::Create() {
  return std::make_unique<SensorGyroscopeInfoCommand>();
}

SensorGyroscopeInfoCommand::SensorGyroscopeInfoCommand() {

}

SensorGyroscopeInfoCommand::~SensorGyroscopeInfoCommand() {

}

std::string SensorGyroscopeInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorGyroscopeInfo";
}


int SensorGyroscopeInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}