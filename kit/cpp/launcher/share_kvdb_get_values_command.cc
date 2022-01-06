// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/share_kvdb_get_values_command.h"

std::unique_ptr<ShareKvDbGetValuesCommand> ShareKvDbGetValuesCommand::Create() {
  return std::make_unique<ShareKvDbGetValuesCommand>();
}

ShareKvDbGetValuesCommand::ShareKvDbGetValuesCommand() {

}

ShareKvDbGetValuesCommand::~ShareKvDbGetValuesCommand() {

}

std::string ShareKvDbGetValuesCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ShareKvDbGetValues";
}


int ShareKvDbGetValuesCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}