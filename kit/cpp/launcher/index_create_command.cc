// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/index_create_command.h"

std::unique_ptr<IndexCreateCommand> IndexCreateCommand::Create() {
  return std::make_unique<IndexCreateCommand>();
}

IndexCreateCommand::IndexCreateCommand() {

}

IndexCreateCommand::~IndexCreateCommand() {

}

std::string IndexCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexCreate";
}


int IndexCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}