// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_model_add_command.h"

std::unique_ptr<MLModelAddCommand> MLModelAddCommand::Create() {
  return std::make_unique<MLModelAddCommand>();
}

MLModelAddCommand::MLModelAddCommand() {

}

MLModelAddCommand::~MLModelAddCommand() {

}

std::string MLModelAddCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLModelAdd";
}


int MLModelAddCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}