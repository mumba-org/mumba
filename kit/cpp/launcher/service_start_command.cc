// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/service_start_command.h"

std::unique_ptr<ServiceStartCommand> ServiceStartCommand::Create() {
  return std::make_unique<ServiceStartCommand>();
}

ServiceStartCommand::ServiceStartCommand() {

}

ServiceStartCommand::~ServiceStartCommand() {

}

std::string ServiceStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ServiceStart";
}


int ServiceStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}