// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/tab_list_command.h"

std::unique_ptr<TabListCommand> TabListCommand::Create() {
  return std::make_unique<TabListCommand>();
}

TabListCommand::TabListCommand() {

}

TabListCommand::~TabListCommand() {

}

std::string TabListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/TabList";
}


int TabListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}