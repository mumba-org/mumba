// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/presentation_close_command.h"

std::unique_ptr<PresentationCloseCommand> PresentationCloseCommand::Create() {
  return std::make_unique<PresentationCloseCommand>();
}

PresentationCloseCommand::PresentationCloseCommand() {

}

PresentationCloseCommand::~PresentationCloseCommand() {

}

std::string PresentationCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PresentationClose";
}


int PresentationCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}