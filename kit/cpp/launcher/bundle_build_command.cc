// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/bundle_build_command.h"

std::unique_ptr<BundleBuildCommand> BundleBuildCommand::Create() {
  return std::make_unique<BundleBuildCommand>();
}

BundleBuildCommand::BundleBuildCommand() {

}
 
BundleBuildCommand::~BundleBuildCommand() {

}

std::string BundleBuildCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BundleBuild";
}

int BundleBuildCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}