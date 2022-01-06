// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/css_set_style_texts_command.h"

std::unique_ptr<CSSSetStyleTextsCommand> CSSSetStyleTextsCommand::Create() {
  return std::make_unique<CSSSetStyleTextsCommand>();
}

CSSSetStyleTextsCommand::CSSSetStyleTextsCommand() {

}

CSSSetStyleTextsCommand::~CSSSetStyleTextsCommand() {

}

std::string CSSSetStyleTextsCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CSSSetStyleTexts";
}


int CSSSetStyleTextsCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}