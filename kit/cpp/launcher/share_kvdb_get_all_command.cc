// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_kvdb_get_all_command.h"

std::unique_ptr<ShareKvDbGetAllCommand> ShareKvDbGetAllCommand::Create() {
  return std::make_unique<ShareKvDbGetAllCommand>();
}

ShareKvDbGetAllCommand::ShareKvDbGetAllCommand() {

}

ShareKvDbGetAllCommand::~ShareKvDbGetAllCommand() {

}

std::string ShareKvDbGetAllCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareKvDbGetAll";
}


int ShareKvDbGetAllCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}