// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cache_item_read_command.h"

std::unique_ptr<CacheItemReadCommand> CacheItemReadCommand::Create() {
  return std::make_unique<CacheItemReadCommand>();
}

CacheItemReadCommand::CacheItemReadCommand() {

}

CacheItemReadCommand::~CacheItemReadCommand() {

}

std::string CacheItemReadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CacheItemRead";
}


int CacheItemReadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}