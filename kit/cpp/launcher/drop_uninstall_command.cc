// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/drop_uninstall_command.h"

std::unique_ptr<DropUninstallCommand> DropUninstallCommand::Create() {
  return std::make_unique<DropUninstallCommand>();
}

DropUninstallCommand::DropUninstallCommand() {

}

DropUninstallCommand::~DropUninstallCommand() {

}

std::string DropUninstallCommand::GetCommandMethod() const {
  return "/mumba.Mumba/DropUninstall";
}

int DropUninstallCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}