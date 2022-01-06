// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cache_item_remove_command.h"

std::unique_ptr<CacheItemRemoveCommand> CacheItemRemoveCommand::Create() {
  return std::make_unique<CacheItemRemoveCommand>();
}

CacheItemRemoveCommand::CacheItemRemoveCommand() {

}

CacheItemRemoveCommand::~CacheItemRemoveCommand() {

}

std::string CacheItemRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CacheItemRemove";
}


int CacheItemRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}