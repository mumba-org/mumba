// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_model_list_command.h"

std::unique_ptr<MLModelListCommand> MLModelListCommand::Create() {
  return std::make_unique<MLModelListCommand>();
}

MLModelListCommand::MLModelListCommand() {

}

MLModelListCommand::~MLModelListCommand() {

}

std::string MLModelListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLModelList";
}


int MLModelListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}