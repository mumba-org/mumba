// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cookie_set_command.h"

std::unique_ptr<CookieSetCommand> CookieSetCommand::Create() {
  return std::make_unique<CookieSetCommand>();
}

CookieSetCommand::CookieSetCommand() {

}

CookieSetCommand::~CookieSetCommand() {

}

std::string CookieSetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CookieSet";
}


int CookieSetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}