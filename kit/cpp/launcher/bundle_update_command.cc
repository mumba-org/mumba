// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/bundle_update_command.h"

std::unique_ptr<BundleUpdateCommand> BundleUpdateCommand::Create() {
  return std::make_unique<BundleUpdateCommand>();
}

BundleUpdateCommand::BundleUpdateCommand() {}

BundleUpdateCommand::~BundleUpdateCommand() {}

std::string BundleUpdateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BundleUpdate";
}

int BundleUpdateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}