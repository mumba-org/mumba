// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/worker_terminate_command.h"

std::unique_ptr<WorkerTerminateCommand> WorkerTerminateCommand::Create() {
  return std::make_unique<WorkerTerminateCommand>();
}

WorkerTerminateCommand::WorkerTerminateCommand() {

}

WorkerTerminateCommand::~WorkerTerminateCommand() {

}

std::string WorkerTerminateCommand::GetCommandMethod() const {
  return "/mumba.Mumba/WorkerTerminate";
}


int WorkerTerminateCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}