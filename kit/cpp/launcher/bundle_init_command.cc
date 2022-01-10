// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/bundle_init_command.h"

std::unique_ptr<BundleInitCommand> BundleInitCommand::Create() {
  return std::make_unique<BundleInitCommand>();
}

BundleInitCommand::BundleInitCommand() {

}
 
BundleInitCommand::~BundleInitCommand() {

}

std::string BundleInitCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BundleInit";
}

int BundleInitCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}