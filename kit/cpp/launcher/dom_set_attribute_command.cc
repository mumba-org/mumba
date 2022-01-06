// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_set_attribute_command.h"

std::unique_ptr<DOMSetAttributeCommand> DOMSetAttributeCommand::Create() {
  return std::make_unique<DOMSetAttributeCommand>();
}

DOMSetAttributeCommand::DOMSetAttributeCommand() {

}

DOMSetAttributeCommand::~DOMSetAttributeCommand() {

}

std::string DOMSetAttributeCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMSetAttribute";
}


int DOMSetAttributeCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}