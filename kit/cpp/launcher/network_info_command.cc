// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/network_info_command.h"

std::unique_ptr<NetworkInfoCommand> NetworkInfoCommand::Create() {
  return std::make_unique<NetworkInfoCommand>();
}

NetworkInfoCommand::NetworkInfoCommand() {

}

NetworkInfoCommand::~NetworkInfoCommand() {

}

std::string NetworkInfoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/NetworkInfo";
}


int NetworkInfoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}