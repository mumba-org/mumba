// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_storage_get_command.h"

std::unique_ptr<DOMStorageGetCommand> DOMStorageGetCommand::Create() {
  return std::make_unique<DOMStorageGetCommand>();
}

DOMStorageGetCommand::DOMStorageGetCommand() {

}

DOMStorageGetCommand::~DOMStorageGetCommand() {

}

std::string DOMStorageGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMStorageGet";
}


int DOMStorageGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}