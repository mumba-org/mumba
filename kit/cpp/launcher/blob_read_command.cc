// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/blob_read_command.h"

std::unique_ptr<BlobReadCommand> BlobReadCommand::Create() {
  return std::make_unique<BlobReadCommand>();
}

BlobReadCommand::BlobReadCommand() {

}

BlobReadCommand::~BlobReadCommand() {

}

std::string BlobReadCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BlobRead";
}


int BlobReadCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}