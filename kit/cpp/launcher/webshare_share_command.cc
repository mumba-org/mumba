// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/webshare_share_command.h"

std::unique_ptr<WebshareShareCommand> WebshareShareCommand::Create() {
  return std::make_unique<WebshareShareCommand>();
}

WebshareShareCommand::WebshareShareCommand() {

}

WebshareShareCommand::~WebshareShareCommand() {

}

std::string WebshareShareCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WebshareShare";
}


int WebshareShareCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}