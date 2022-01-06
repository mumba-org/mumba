// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/presentation_reconnect_command.h"

std::unique_ptr<PresentationReconnectCommand> PresentationReconnectCommand::Create() {
  return std::make_unique<PresentationReconnectCommand>();
}

PresentationReconnectCommand::PresentationReconnectCommand() {

}

PresentationReconnectCommand::~PresentationReconnectCommand() {

}

std::string PresentationReconnectCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PresentationReconnect";
}


int PresentationReconnectCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}