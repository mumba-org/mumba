// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_add_script_command.h"

std::unique_ptr<PageAddScriptCommand> PageAddScriptCommand::Create() {
  return std::make_unique<PageAddScriptCommand>();
}

PageAddScriptCommand::PageAddScriptCommand() {

}

PageAddScriptCommand::~PageAddScriptCommand() {

}

std::string PageAddScriptCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageAddScript";
}


int PageAddScriptCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}