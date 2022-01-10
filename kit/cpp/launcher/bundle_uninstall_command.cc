// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/bundle_uninstall_command.h"

std::unique_ptr<BundleUninstallCommand> BundleUninstallCommand::Create() {
  return std::make_unique<BundleUninstallCommand>();
}

BundleUninstallCommand::BundleUninstallCommand() {

}

BundleUninstallCommand::~BundleUninstallCommand() {

}

std::string BundleUninstallCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BundleUninstall";
}

int BundleUninstallCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}