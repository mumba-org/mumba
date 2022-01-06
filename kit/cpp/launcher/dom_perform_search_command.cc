// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_perform_search_command.h"

std::unique_ptr<DOMPerformSearchCommand> DOMPerformSearchCommand::Create() {
  return std::make_unique<DOMPerformSearchCommand>();
}

DOMPerformSearchCommand::DOMPerformSearchCommand() {

}

DOMPerformSearchCommand::~DOMPerformSearchCommand() {

}

std::string DOMPerformSearchCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMPerformSearch";
}


int DOMPerformSearchCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}