// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_peer_service_list_command.h"

std::unique_ptr<SharePeerServiceListCommand> SharePeerServiceListCommand::Create() {
  return std::make_unique<SharePeerServiceListCommand>();
}

SharePeerServiceListCommand::SharePeerServiceListCommand() {

}

SharePeerServiceListCommand::~SharePeerServiceListCommand() {

}

std::string SharePeerServiceListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SharePeerServiceList";
}


int SharePeerServiceListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}