// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_stop_loading_command.h"

std::unique_ptr<PageStopLoadingCommand> PageStopLoadingCommand::Create() {
  return std::make_unique<PageStopLoadingCommand>();
}

PageStopLoadingCommand::PageStopLoadingCommand() {

}

PageStopLoadingCommand::~PageStopLoadingCommand() {

}

std::string PageStopLoadingCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageStopLoading";
}


int PageStopLoadingCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}