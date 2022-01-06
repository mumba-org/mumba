// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/tab_activate_command.h"

std::unique_ptr<TabActivateCommand> TabActivateCommand::Create() {
  return std::make_unique<TabActivateCommand>();
}

TabActivateCommand::TabActivateCommand() {

}

TabActivateCommand::~TabActivateCommand() {

}

std::string TabActivateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/TabActivate";
}


int TabActivateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}