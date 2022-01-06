// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/blob_list_command.h"

std::unique_ptr<BlobListCommand> BlobListCommand::Create() {
  return std::make_unique<BlobListCommand>();
}

BlobListCommand::BlobListCommand() {

}

BlobListCommand::~BlobListCommand() {

}

std::string BlobListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BlobList";
}


int BlobListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}