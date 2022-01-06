// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/css_set_stylesheet_text_command.h"

std::unique_ptr<CSSSetStyleSheetTextCommand> CSSSetStyleSheetTextCommand::Create() {
  return std::make_unique<CSSSetStyleSheetTextCommand>();
}

CSSSetStyleSheetTextCommand::CSSSetStyleSheetTextCommand() {

}

CSSSetStyleSheetTextCommand::~CSSSetStyleSheetTextCommand() {

}

std::string CSSSetStyleSheetTextCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CSSSetStyleSheetText";
}


int CSSSetStyleSheetTextCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}