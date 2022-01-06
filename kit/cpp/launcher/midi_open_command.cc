// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/midi_open_command.h"

std::unique_ptr<MidiOpenCommand> MidiOpenCommand::Create() {
  return std::make_unique<MidiOpenCommand>();
}

MidiOpenCommand::MidiOpenCommand() {

}

MidiOpenCommand::~MidiOpenCommand() {

}

std::string MidiOpenCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MidiOpen";
}


int MidiOpenCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}