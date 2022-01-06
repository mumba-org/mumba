// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/worker_list_command.h"

std::unique_ptr<WorkerListCommand> WorkerListCommand::Create() {
  return std::make_unique<WorkerListCommand>();
}

WorkerListCommand::WorkerListCommand() {

}

WorkerListCommand::~WorkerListCommand() {

}

std::string WorkerListCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WorkerList";
}


int WorkerListCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}