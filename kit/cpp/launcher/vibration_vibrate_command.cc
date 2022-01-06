// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/vibration_vibrate_command.h"

std::unique_ptr<VibrationVibrateCommand> VibrationVibrateCommand::Create() {
  return std::make_unique<VibrationVibrateCommand>();
}

VibrationVibrateCommand::VibrationVibrateCommand() {

}

VibrationVibrateCommand::~VibrationVibrateCommand() {

}

std::string VibrationVibrateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/VibrationVibrate";
}


int VibrationVibrateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}