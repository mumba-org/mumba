// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_get_all_command.h"

std::unique_ptr<IndexedDBGetAllCommand> IndexedDBGetAllCommand::Create() {
  return std::make_unique<IndexedDBGetAllCommand>();
}

IndexedDBGetAllCommand::IndexedDBGetAllCommand() {

}

IndexedDBGetAllCommand::~IndexedDBGetAllCommand() {

}

std::string IndexedDBGetAllCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBGetAll";
}


int IndexedDBGetAllCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}