// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_set_outer_html_command.h"

std::unique_ptr<DOMSetOuterHtmlCommand> DOMSetOuterHtmlCommand::Create() {
  return std::make_unique<DOMSetOuterHtmlCommand>();
}

DOMSetOuterHtmlCommand::DOMSetOuterHtmlCommand() {

}

DOMSetOuterHtmlCommand::~DOMSetOuterHtmlCommand() {

}

std::string DOMSetOuterHtmlCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMSetOuterHtml";
}


int DOMSetOuterHtmlCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}