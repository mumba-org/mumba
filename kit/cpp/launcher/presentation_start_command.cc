// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/presentation_start_command.h"

std::unique_ptr<PresentationStartCommand> PresentationStartCommand::Create() {
  return std::make_unique<PresentationStartCommand>();
}

PresentationStartCommand::PresentationStartCommand() {

}

PresentationStartCommand::~PresentationStartCommand() {

}

std::string PresentationStartCommand::GetCommandMethod() const {
  return "/mumba.Mumba/PresentationStart";
}


int PresentationStartCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}