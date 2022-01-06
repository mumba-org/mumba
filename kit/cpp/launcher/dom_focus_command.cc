// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_focus_command.h"

std::unique_ptr<DOMFocusCommand> DOMFocusCommand::Create() {
  return std::make_unique<DOMFocusCommand>();
}

DOMFocusCommand::DOMFocusCommand() {

}

DOMFocusCommand::~DOMFocusCommand() {

}

std::string DOMFocusCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMFocus";
}


int DOMFocusCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}