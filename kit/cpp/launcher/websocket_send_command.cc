// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/websocket_send_command.h"

std::unique_ptr<WebsocketSendCommand> WebsocketSendCommand::Create() {
  return std::make_unique<WebsocketSendCommand>();
}

WebsocketSendCommand::WebsocketSendCommand() {

}

WebsocketSendCommand::~WebsocketSendCommand() {

}

std::string WebsocketSendCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WebsocketSend";
}


int WebsocketSendCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}