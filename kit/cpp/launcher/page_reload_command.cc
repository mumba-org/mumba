// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_reload_command.h"

std::unique_ptr<PageReloadCommand> PageReloadCommand::Create() {
  return std::make_unique<PageReloadCommand>();
}

PageReloadCommand::PageReloadCommand() {

}

PageReloadCommand::~PageReloadCommand() {

}

std::string PageReloadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageReload";
}


int PageReloadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}