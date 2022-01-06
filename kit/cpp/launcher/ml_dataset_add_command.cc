// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_dataset_add_command.h"

std::unique_ptr<MLDatasetAddCommand> MLDatasetAddCommand::Create() {
  return std::make_unique<MLDatasetAddCommand>();
}

MLDatasetAddCommand::MLDatasetAddCommand() {

}

MLDatasetAddCommand::~MLDatasetAddCommand() {

}

std::string MLDatasetAddCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLDatasetAdd";
}


int MLDatasetAddCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}