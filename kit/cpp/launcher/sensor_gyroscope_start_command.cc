// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/sensor_gyroscope_start_command.h"

std::unique_ptr<SensorGyroscopeStartCommand> SensorGyroscopeStartCommand::Create() {
  return std::make_unique<SensorGyroscopeStartCommand>();
}

SensorGyroscopeStartCommand::SensorGyroscopeStartCommand() {

}

SensorGyroscopeStartCommand::~SensorGyroscopeStartCommand() {

}

std::string SensorGyroscopeStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SensorGyroscopeStart";
}


int SensorGyroscopeStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}