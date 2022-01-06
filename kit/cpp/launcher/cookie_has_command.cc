// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cookie_has_command.h"

std::unique_ptr<CookieHasCommand> CookieHasCommand::Create() {
  return std::make_unique<CookieHasCommand>();
}

CookieHasCommand::CookieHasCommand() {

}

CookieHasCommand::~CookieHasCommand() {

}

std::string CookieHasCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CookieHas";
}


int CookieHasCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}