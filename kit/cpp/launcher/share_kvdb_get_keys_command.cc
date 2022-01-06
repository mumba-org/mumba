// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_kvdb_get_keys_command.h"

std::unique_ptr<ShareKvDbGetKeysCommand> ShareKvDbGetKeysCommand::Create() {
  return std::make_unique<ShareKvDbGetKeysCommand>();
}

ShareKvDbGetKeysCommand::ShareKvDbGetKeysCommand() {

}

ShareKvDbGetKeysCommand::~ShareKvDbGetKeysCommand() {

}

std::string ShareKvDbGetKeysCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareKvDbGetKeys";
}


int ShareKvDbGetKeysCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}