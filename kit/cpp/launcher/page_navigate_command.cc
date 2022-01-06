// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_navigate_command.h"

std::unique_ptr<PageNavigateCommand> PageNavigateCommand::Create() {
  return std::make_unique<PageNavigateCommand>();
}

PageNavigateCommand::PageNavigateCommand() {

}

PageNavigateCommand::~PageNavigateCommand() {

}

std::string PageNavigateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageNavigate";
}

int PageNavigateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}