// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/fetch_close_command.h"

std::unique_ptr<FetchCloseCommand> FetchCloseCommand::Create() {
  return std::make_unique<FetchCloseCommand>();
}

FetchCloseCommand::FetchCloseCommand() {

}

FetchCloseCommand::~FetchCloseCommand() {

}

std::string FetchCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FetchClose";
}


int FetchCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}