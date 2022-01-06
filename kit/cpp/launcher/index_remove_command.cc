// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/index_remove_command.h"

std::unique_ptr<IndexRemoveCommand> IndexRemoveCommand::Create() {
  return std::make_unique<IndexRemoveCommand>();
}

IndexRemoveCommand::IndexRemoveCommand() {

}

IndexRemoveCommand::~IndexRemoveCommand() {

}

std::string IndexRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexRemove";
}


int IndexRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}