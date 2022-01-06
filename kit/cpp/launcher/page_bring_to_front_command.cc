// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_bring_to_front_command.h"

std::unique_ptr<PageBringToFrontCommand> PageBringToFrontCommand::Create() {
  return std::make_unique<PageBringToFrontCommand>();
}

PageBringToFrontCommand::PageBringToFrontCommand() {

}

PageBringToFrontCommand::~PageBringToFrontCommand() {

}

std::string PageBringToFrontCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageBringToFront";
}


int PageBringToFrontCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}