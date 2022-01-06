// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/websocket_start_command.h"

std::unique_ptr<WebsocketStartCommand> WebsocketStartCommand::Create() {
  return std::make_unique<WebsocketStartCommand>();
}

WebsocketStartCommand::WebsocketStartCommand() {

}

WebsocketStartCommand::~WebsocketStartCommand() {

}

std::string WebsocketStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WebsocketStart";
}


int WebsocketStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}