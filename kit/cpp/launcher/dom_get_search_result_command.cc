// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_get_search_result_command.h"

std::unique_ptr<DOMGetSearchResultCommand> DOMGetSearchResultCommand::Create() {
  return std::make_unique<DOMGetSearchResultCommand>();
}

DOMGetSearchResultCommand::DOMGetSearchResultCommand() {

}

DOMGetSearchResultCommand::~DOMGetSearchResultCommand() {

}

std::string DOMGetSearchResultCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMGetSearchResult";
}


int DOMGetSearchResultCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}