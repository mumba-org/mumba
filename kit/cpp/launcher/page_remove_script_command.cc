// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_remove_script_command.h"

std::unique_ptr<PageRemoveScriptCommand> PageRemoveScriptCommand::Create() {
  return std::make_unique<PageRemoveScriptCommand>();
}

PageRemoveScriptCommand::PageRemoveScriptCommand() {

}

PageRemoveScriptCommand::~PageRemoveScriptCommand() {

}

std::string PageRemoveScriptCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageRemoveScript";
}


int PageRemoveScriptCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}