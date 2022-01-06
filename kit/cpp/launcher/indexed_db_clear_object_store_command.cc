// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_clear_object_store_command.h"

std::unique_ptr<IndexedDBClearObjectStoreCommand> IndexedDBClearObjectStoreCommand::Create() {
  return std::make_unique<IndexedDBClearObjectStoreCommand>();
}

IndexedDBClearObjectStoreCommand::IndexedDBClearObjectStoreCommand() {

}

IndexedDBClearObjectStoreCommand::~IndexedDBClearObjectStoreCommand() {

}

std::string IndexedDBClearObjectStoreCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBClearObjectStore";
}


int IndexedDBClearObjectStoreCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}