// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/repo_remove_command.h"

std::unique_ptr<RepoRemoveCommand> RepoRemoveCommand::Create() {
  return std::make_unique<RepoRemoveCommand>();
}

RepoRemoveCommand::RepoRemoveCommand() {

}

RepoRemoveCommand::~RepoRemoveCommand() {

}

std::string RepoRemoveCommand::GetCommandMethod() const {
  return "/mumba.Mumba/RepoRemove";
}


int RepoRemoveCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}