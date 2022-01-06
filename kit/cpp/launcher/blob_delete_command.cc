// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/blob_delete_command.h"

std::unique_ptr<BlobDeleteCommand> BlobDeleteCommand::Create() {
  return std::make_unique<BlobDeleteCommand>();
}

BlobDeleteCommand::BlobDeleteCommand() {

}

BlobDeleteCommand::~BlobDeleteCommand() {

}

std::string BlobDeleteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BlobDelete";
}


int BlobDeleteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}