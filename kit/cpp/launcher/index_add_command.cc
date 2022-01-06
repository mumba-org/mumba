// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/index_add_command.h"

std::unique_ptr<IndexAddCommand> IndexAddCommand::Create() {
  return std::make_unique<IndexAddCommand>();
}

IndexAddCommand::IndexAddCommand() {

}

IndexAddCommand::~IndexAddCommand() {

}

std::string IndexAddCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexAdd";
}


int IndexAddCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}