// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_dataset_list_command.h"

std::unique_ptr<MLDatasetListCommand> MLDatasetListCommand::Create() {
  return std::make_unique<MLDatasetListCommand>();
}

MLDatasetListCommand::MLDatasetListCommand() {

}

MLDatasetListCommand::~MLDatasetListCommand() {

}

std::string MLDatasetListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLDatasetList";
}


int MLDatasetListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}