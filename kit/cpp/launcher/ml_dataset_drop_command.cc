// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_dataset_drop_command.h"

std::unique_ptr<MLDatasetDropCommand> MLDatasetDropCommand::Create() {
  return std::make_unique<MLDatasetDropCommand>();
}

MLDatasetDropCommand::MLDatasetDropCommand() {

}

MLDatasetDropCommand::~MLDatasetDropCommand() {

}

std::string MLDatasetDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLDatasetDrop";
}


int MLDatasetDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}