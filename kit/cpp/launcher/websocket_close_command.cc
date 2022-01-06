// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/websocket_close_command.h"

std::unique_ptr<WebsocketCloseCommand> WebsocketCloseCommand::Create() {
  return std::make_unique<WebsocketCloseCommand>();
}

WebsocketCloseCommand::WebsocketCloseCommand() {

}

WebsocketCloseCommand::~WebsocketCloseCommand() {

}

std::string WebsocketCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WebsocketClose";
}


int WebsocketCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}