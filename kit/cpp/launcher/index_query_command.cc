// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/index_query_command.h"

std::unique_ptr<IndexQueryCommand> IndexQueryCommand::Create() {
  return std::make_unique<IndexQueryCommand>();
}

IndexQueryCommand::IndexQueryCommand() {

}

IndexQueryCommand::~IndexQueryCommand() {

}

std::string IndexQueryCommand::GetCommandMethod() const {
  return "/mumba.Mumba/IndexQuery";
}


int IndexQueryCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}