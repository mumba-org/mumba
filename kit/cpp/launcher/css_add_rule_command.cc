// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/css_add_rule_command.h"

std::unique_ptr<CSSAddRuleCommand> CSSAddRuleCommand::Create() {
  return std::make_unique<CSSAddRuleCommand>();
}

CSSAddRuleCommand::CSSAddRuleCommand() {

}

CSSAddRuleCommand::~CSSAddRuleCommand() {

}

std::string CSSAddRuleCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CSSAddRule";
}


int CSSAddRuleCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}