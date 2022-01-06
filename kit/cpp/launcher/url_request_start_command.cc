// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/url_request_start_command.h"

std::unique_ptr<URLRequestStartCommand> URLRequestStartCommand::Create() {
  return std::make_unique<URLRequestStartCommand>();
}

URLRequestStartCommand::URLRequestStartCommand() {

}

URLRequestStartCommand::~URLRequestStartCommand() {

}

std::string URLRequestStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/URLRequestStart";
}


int URLRequestStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}