// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_peer_list_command.h"

std::unique_ptr<SharePeerListCommand> SharePeerListCommand::Create() {
  return std::make_unique<SharePeerListCommand>();
}

SharePeerListCommand::SharePeerListCommand() {

}

SharePeerListCommand::~SharePeerListCommand() {

}

std::string SharePeerListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SharePeerList";
}


int SharePeerListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}