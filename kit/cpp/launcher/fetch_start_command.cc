// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/fetch_start_command.h"

std::unique_ptr<FetchStartCommand> FetchStartCommand::Create() {
  return std::make_unique<FetchStartCommand>();
}

FetchStartCommand::FetchStartCommand() {

}

FetchStartCommand::~FetchStartCommand() {

}

std::string FetchStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/FetchStart";
}


int FetchStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}