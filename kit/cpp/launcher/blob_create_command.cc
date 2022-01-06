// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/blob_create_command.h"

std::unique_ptr<BlobCreateCommand> BlobCreateCommand::Create() {
  return std::make_unique<BlobCreateCommand>();
}

BlobCreateCommand::BlobCreateCommand() {

}

BlobCreateCommand::~BlobCreateCommand() {

}

std::string BlobCreateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BlobCreate";
}


int BlobCreateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}