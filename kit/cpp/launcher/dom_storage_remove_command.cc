// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_storage_remove_command.h"

std::unique_ptr<DOMStorageRemoveCommand> DOMStorageRemoveCommand::Create() {
  return std::make_unique<DOMStorageRemoveCommand>();
}

DOMStorageRemoveCommand::DOMStorageRemoveCommand() {

}

DOMStorageRemoveCommand::~DOMStorageRemoveCommand() {

}

std::string DOMStorageRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMStorageRemove";
}


int DOMStorageRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}