// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_predictor_install_command.h"

std::unique_ptr<MLPredictorInstallCommand> MLPredictorInstallCommand::Create() {
  return std::make_unique<MLPredictorInstallCommand>();
}

MLPredictorInstallCommand::MLPredictorInstallCommand() {

}

MLPredictorInstallCommand::~MLPredictorInstallCommand() {

}

std::string MLPredictorInstallCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLPredictorInstall";
}


int MLPredictorInstallCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}