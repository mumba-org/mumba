// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/indexed_db_request_data_command.h"

std::unique_ptr<IndexedDBRequestDataCommand> IndexedDBRequestDataCommand::Create() {
  return std::make_unique<IndexedDBRequestDataCommand>();
}

IndexedDBRequestDataCommand::IndexedDBRequestDataCommand() {

}

IndexedDBRequestDataCommand::~IndexedDBRequestDataCommand() {

}

std::string IndexedDBRequestDataCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexedDBRequestData";
}


int IndexedDBRequestDataCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}