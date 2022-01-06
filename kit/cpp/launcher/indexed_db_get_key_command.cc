// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_get_key_command.h"

std::unique_ptr<IndexedDBGetKeyCommand> IndexedDBGetKeyCommand::Create() {
  return std::make_unique<IndexedDBGetKeyCommand>();
}

IndexedDBGetKeyCommand::IndexedDBGetKeyCommand() {

}

IndexedDBGetKeyCommand::~IndexedDBGetKeyCommand() {

}

std::string IndexedDBGetKeyCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBGetKey";
}


int IndexedDBGetKeyCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}