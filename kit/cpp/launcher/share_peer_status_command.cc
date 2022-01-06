// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_peer_status_command.h"

std::unique_ptr<SharePeerStatusCommand> SharePeerStatusCommand::Create() {
  return std::make_unique<SharePeerStatusCommand>();
}

SharePeerStatusCommand::SharePeerStatusCommand() {

}

SharePeerStatusCommand::~SharePeerStatusCommand() {

}

std::string SharePeerStatusCommand::GetCommandMethod() const {
  return "/mumba.Mumba/SharePeerStatus";
}


int SharePeerStatusCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}