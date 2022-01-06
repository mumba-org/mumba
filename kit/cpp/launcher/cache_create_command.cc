// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cache_create_command.h"

std::unique_ptr<CacheCreateCommand> CacheCreateCommand::Create() {
  return std::make_unique<CacheCreateCommand>();
}

CacheCreateCommand::CacheCreateCommand() {

}

CacheCreateCommand::~CacheCreateCommand() {

}

std::string CacheCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CacheCreate";
}


int CacheCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}