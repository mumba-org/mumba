// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cookie_get_command.h"

std::unique_ptr<CookieGetCommand> CookieGetCommand::Create() {
  return std::make_unique<CookieGetCommand>();
}

CookieGetCommand::CookieGetCommand() {

}

CookieGetCommand::~CookieGetCommand() {

}

std::string CookieGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CookieGet";
}


int CookieGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}