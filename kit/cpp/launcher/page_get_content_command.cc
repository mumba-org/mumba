// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_get_content_command.h"

std::unique_ptr<PageGetContentCommand> PageGetContentCommand::Create() {
  return std::make_unique<PageGetContentCommand>();
}

PageGetContentCommand::PageGetContentCommand() {

}

PageGetContentCommand::~PageGetContentCommand() {

}

std::string PageGetContentCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageGetContent";
}


int PageGetContentCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}