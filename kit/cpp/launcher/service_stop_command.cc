// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/service_stop_command.h"

std::unique_ptr<ServiceStopCommand> ServiceStopCommand::Create() {
  return std::make_unique<ServiceStopCommand>();
}

ServiceStopCommand::ServiceStopCommand() {

}

ServiceStopCommand::~ServiceStopCommand() {

}

std::string ServiceStopCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ServiceStop";
}


int ServiceStopCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}