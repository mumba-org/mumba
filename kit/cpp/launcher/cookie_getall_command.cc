// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/cookie_getall_command.h"

std::unique_ptr<CookieGetAllCommand> CookieGetAllCommand::Create() {
  return std::make_unique<CookieGetAllCommand>();
}

CookieGetAllCommand::CookieGetAllCommand() {

}

CookieGetAllCommand::~CookieGetAllCommand() {

}

std::string CookieGetAllCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CookieGetAll";
}


int CookieGetAllCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}