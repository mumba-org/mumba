// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cache_item_add_command.h"

std::unique_ptr<CacheItemAddCommand> CacheItemAddCommand::Create() {
  return std::make_unique<CacheItemAddCommand>();
}

CacheItemAddCommand::CacheItemAddCommand() {

}

CacheItemAddCommand::~CacheItemAddCommand() {

}

std::string CacheItemAddCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CacheItemAdd";
}


int CacheItemAddCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}