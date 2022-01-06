// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/repo_list_command.h"

std::unique_ptr<RepoListCommand> RepoListCommand::Create() {
  return std::make_unique<RepoListCommand>();
}

RepoListCommand::RepoListCommand() {

}

RepoListCommand::~RepoListCommand() {

}

std::string RepoListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RepoList";
}


int RepoListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}