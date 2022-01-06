// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/index_drop_command.h"

std::unique_ptr<IndexDropCommand> IndexDropCommand::Create() {
  return std::make_unique<IndexDropCommand>();
}

IndexDropCommand::IndexDropCommand() {

}

IndexDropCommand::~IndexDropCommand() {

}

std::string IndexDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexDrop";
}


int IndexDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}