// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cache_drop_command.h"

std::unique_ptr<CacheDropCommand> CacheDropCommand::Create() {
  return std::make_unique<CacheDropCommand>();
}

CacheDropCommand::CacheDropCommand() {

}

CacheDropCommand::~CacheDropCommand() {

}

std::string CacheDropCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CacheDrop";
}


int CacheDropCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}