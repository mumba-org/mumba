// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_get_attributes_command.h"

std::unique_ptr<DOMGetAttributesCommand> DOMGetAttributesCommand::Create() {
  return std::make_unique<DOMGetAttributesCommand>();
}

DOMGetAttributesCommand::DOMGetAttributesCommand() {

}

DOMGetAttributesCommand::~DOMGetAttributesCommand() {

}

std::string DOMGetAttributesCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMGetAttributes";
}


int DOMGetAttributesCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}