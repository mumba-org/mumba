// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_storage_set_command.h"

std::unique_ptr<DOMStorageSetCommand> DOMStorageSetCommand::Create() {
  return std::make_unique<DOMStorageSetCommand>();
}

DOMStorageSetCommand::DOMStorageSetCommand() {

}

DOMStorageSetCommand::~DOMStorageSetCommand() {

}

std::string DOMStorageSetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMStorageSet";
}


int DOMStorageSetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}