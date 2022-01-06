// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_query_selector_command.h"

std::unique_ptr<DOMQuerySelectorCommand> DOMQuerySelectorCommand::Create() {
  return std::make_unique<DOMQuerySelectorCommand>();
}

DOMQuerySelectorCommand::DOMQuerySelectorCommand() {

}

DOMQuerySelectorCommand::~DOMQuerySelectorCommand() {

}

std::string DOMQuerySelectorCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMQuerySelector";
}


int DOMQuerySelectorCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}