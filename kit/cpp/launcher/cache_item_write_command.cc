// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cache_item_write_command.h"

std::unique_ptr<CacheItemWriteCommand> CacheItemWriteCommand::Create() {
  return std::make_unique<CacheItemWriteCommand>();
}

CacheItemWriteCommand::CacheItemWriteCommand() {

}

CacheItemWriteCommand::~CacheItemWriteCommand() {

}

std::string CacheItemWriteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CacheItemWrite";
}


int CacheItemWriteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}