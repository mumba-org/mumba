// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/url_request_close_command.h"

std::unique_ptr<URLRequestCloseCommand> URLRequestCloseCommand::Create() {
  return std::make_unique<URLRequestCloseCommand>();
}

URLRequestCloseCommand::URLRequestCloseCommand() {

}

URLRequestCloseCommand::~URLRequestCloseCommand() {

}

std::string URLRequestCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/URLRequestClose";
}


int URLRequestCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}