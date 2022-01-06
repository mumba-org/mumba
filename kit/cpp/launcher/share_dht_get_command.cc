// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_dht_get_command.h"

std::unique_ptr<ShareDHTGetCommand> ShareDHTGetCommand::Create() {
  return std::make_unique<ShareDHTGetCommand>();
}

ShareDHTGetCommand::ShareDHTGetCommand() {

}

ShareDHTGetCommand::~ShareDHTGetCommand() {

}

std::string ShareDHTGetCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareDHTGet";
}


int ShareDHTGetCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}