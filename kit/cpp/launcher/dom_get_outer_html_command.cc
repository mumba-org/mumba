// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/dom_get_outer_html_command.h"

std::unique_ptr<DOMGetOuterHtmlCommand> DOMGetOuterHtmlCommand::Create() {
  return std::make_unique<DOMGetOuterHtmlCommand>();
}

DOMGetOuterHtmlCommand::DOMGetOuterHtmlCommand() {

}

DOMGetOuterHtmlCommand::~DOMGetOuterHtmlCommand() {

}

std::string DOMGetOuterHtmlCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DOMGetOuterHtml";
}


int DOMGetOuterHtmlCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}