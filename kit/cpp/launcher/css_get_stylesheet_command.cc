// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/css_get_stylesheet_command.h"

std::unique_ptr<CSSGetStyleSheetCommand> CSSGetStyleSheetCommand::Create() {
  return std::make_unique<CSSGetStyleSheetCommand>();
}

CSSGetStyleSheetCommand::CSSGetStyleSheetCommand() {

}

CSSGetStyleSheetCommand::~CSSGetStyleSheetCommand() {

}

std::string CSSGetStyleSheetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CSSGetStyleSheet";
}


int CSSGetStyleSheetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}