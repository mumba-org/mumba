// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/repo_install_command.h"

std::unique_ptr<RepoInstallCommand> RepoInstallCommand::Create() {
  return std::make_unique<RepoInstallCommand>();
}

RepoInstallCommand::RepoInstallCommand() {

}

RepoInstallCommand::~RepoInstallCommand() {

}

std::string RepoInstallCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RepoInstall";
}


int RepoInstallCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}