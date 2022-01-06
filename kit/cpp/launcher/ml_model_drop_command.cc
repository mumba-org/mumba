// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/ml_model_drop_command.h"

std::unique_ptr<MLModelDropCommand> MLModelDropCommand::Create() {
  return std::make_unique<MLModelDropCommand>();
}

MLModelDropCommand::MLModelDropCommand() {

}

MLModelDropCommand::~MLModelDropCommand() {

}

std::string MLModelDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MLModelDrop";
}


int MLModelDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}