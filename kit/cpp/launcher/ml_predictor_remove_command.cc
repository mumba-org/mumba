// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_predictor_remove_command.h"

std::unique_ptr<MLPredictorRemoveCommand> MLPredictorRemoveCommand::Create() {
  return std::make_unique<MLPredictorRemoveCommand>();
}

MLPredictorRemoveCommand::MLPredictorRemoveCommand() {

}

MLPredictorRemoveCommand::~MLPredictorRemoveCommand() {

}

std::string MLPredictorRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLPredictorRemove";
}


int MLPredictorRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}