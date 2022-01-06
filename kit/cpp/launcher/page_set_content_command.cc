// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_set_content_command.h"

std::unique_ptr<PageSetContentCommand> PageSetContentCommand::Create() {
  return std::make_unique<PageSetContentCommand>();
}

PageSetContentCommand::PageSetContentCommand() {

}

PageSetContentCommand::~PageSetContentCommand() {

}

std::string PageSetContentCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageSetContent";
}


int PageSetContentCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}