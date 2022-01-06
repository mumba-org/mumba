// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/blob_write_command.h"

std::unique_ptr<BlobWriteCommand> BlobWriteCommand::Create() {
  return std::make_unique<BlobWriteCommand>();
}

BlobWriteCommand::BlobWriteCommand() {

}

BlobWriteCommand::~BlobWriteCommand() {

}

std::string BlobWriteCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BlobWrite";
}


int BlobWriteCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}