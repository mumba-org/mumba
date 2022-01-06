// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_count_command.h"

std::unique_ptr<IndexedDBCountCommand> IndexedDBCountCommand::Create() {
  return std::make_unique<IndexedDBCountCommand>();
}

IndexedDBCountCommand::IndexedDBCountCommand() {

}

IndexedDBCountCommand::~IndexedDBCountCommand() {

}

std::string IndexedDBCountCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBCount";
}


int IndexedDBCountCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}