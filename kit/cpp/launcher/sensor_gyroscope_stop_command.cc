// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_gyroscope_stop_command.h"

std::unique_ptr<SensorGyroscopeStopCommand> SensorGyroscopeStopCommand::Create() {
  return std::make_unique<SensorGyroscopeStopCommand>();
}

SensorGyroscopeStopCommand::SensorGyroscopeStopCommand() {

}

SensorGyroscopeStopCommand::~SensorGyroscopeStopCommand() {

}

std::string SensorGyroscopeStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorGyroscopeStop";
}


int SensorGyroscopeStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}