// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_set_node_value_command.h"

std::unique_ptr<DOMSetNodeValueCommand> DOMSetNodeValueCommand::Create() {
  return std::make_unique<DOMSetNodeValueCommand>();
}

DOMSetNodeValueCommand::DOMSetNodeValueCommand() {

}

DOMSetNodeValueCommand::~DOMSetNodeValueCommand() {

}

std::string DOMSetNodeValueCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMSetNodeValue";
}


int DOMSetNodeValueCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}