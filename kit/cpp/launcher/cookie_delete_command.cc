// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cookie_delete_command.h"

std::unique_ptr<CookieDeleteCommand> CookieDeleteCommand::Create() {
  return std::make_unique<CookieDeleteCommand>();
}

CookieDeleteCommand::CookieDeleteCommand() {

}

CookieDeleteCommand::~CookieDeleteCommand() {

}

std::string CookieDeleteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CookieDelete";
}


int CookieDeleteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}