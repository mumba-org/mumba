// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/service_list_command.h"

std::unique_ptr<ServiceListCommand> ServiceListCommand::Create() {
  return std::make_unique<ServiceListCommand>();
}

ServiceListCommand::ServiceListCommand() {

}

ServiceListCommand::~ServiceListCommand() {

}

std::string ServiceListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ServiceList";
}


int ServiceListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}