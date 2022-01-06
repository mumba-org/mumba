// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_screenshot_command.h"

std::unique_ptr<PageScreenshotCommand> PageScreenshotCommand::Create() {
  return std::make_unique<PageScreenshotCommand>();
}

PageScreenshotCommand::PageScreenshotCommand() {

}

PageScreenshotCommand::~PageScreenshotCommand() {

}

std::string PageScreenshotCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageScreenshot";
}


int PageScreenshotCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}