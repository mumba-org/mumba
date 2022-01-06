// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_close_command.h"

std::unique_ptr<PageCloseCommand> PageCloseCommand::Create() {
  return std::make_unique<PageCloseCommand>();
}

PageCloseCommand::PageCloseCommand() {

}

PageCloseCommand::~PageCloseCommand() {

}

std::string PageCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageClose";
}


int PageCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}