// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/page_save_to_pdf_command.h"

std::unique_ptr<PageSaveToPdfCommand> PageSaveToPdfCommand::Create() {
  return std::make_unique<PageSaveToPdfCommand>();
}

PageSaveToPdfCommand::PageSaveToPdfCommand() {

}

PageSaveToPdfCommand::~PageSaveToPdfCommand() {

}

std::string PageSaveToPdfCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PageSaveToPdf";
}


int PageSaveToPdfCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}