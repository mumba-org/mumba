// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_delete_db_command.h"

std::unique_ptr<IndexedDBDeleteDBCommand> IndexedDBDeleteDBCommand::Create() {
  return std::make_unique<IndexedDBDeleteDBCommand>();
}

IndexedDBDeleteDBCommand::IndexedDBDeleteDBCommand() {

}

IndexedDBDeleteDBCommand::~IndexedDBDeleteDBCommand() {

}

std::string IndexedDBDeleteDBCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBDeleteDB";
}


int IndexedDBDeleteDBCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}