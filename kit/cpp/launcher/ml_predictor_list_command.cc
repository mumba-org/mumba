// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_predictor_list_command.h"

std::unique_ptr<MLPredictorListCommand> MLPredictorListCommand::Create() {
  return std::make_unique<MLPredictorListCommand>();
}

MLPredictorListCommand::MLPredictorListCommand() {

}

MLPredictorListCommand::~MLPredictorListCommand() {

}

std::string MLPredictorListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLPredictorList";
}


int MLPredictorListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}