// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_set_node_name_command.h"

std::unique_ptr<DOMSetNodeNameCommand> DOMSetNodeNameCommand::Create() {
  return std::make_unique<DOMSetNodeNameCommand>();
}

DOMSetNodeNameCommand::DOMSetNodeNameCommand() {

}

DOMSetNodeNameCommand::~DOMSetNodeNameCommand() {

}

std::string DOMSetNodeNameCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMSetNodeName";
}


int DOMSetNodeNameCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}