// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_get_command.h"

std::unique_ptr<IndexedDBGetCommand> IndexedDBGetCommand::Create() {
  return std::make_unique<IndexedDBGetCommand>();
}

IndexedDBGetCommand::IndexedDBGetCommand() {

}

IndexedDBGetCommand::~IndexedDBGetCommand() {

}

std::string IndexedDBGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBGet";
}


int IndexedDBGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}