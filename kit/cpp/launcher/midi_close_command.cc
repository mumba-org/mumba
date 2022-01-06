// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/midi_close_command.h"

std::unique_ptr<MidiCloseCommand> MidiCloseCommand::Create() {
  return std::make_unique<MidiCloseCommand>();
}

MidiCloseCommand::MidiCloseCommand() {

}

MidiCloseCommand::~MidiCloseCommand() {

}

std::string MidiCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MidiClose";
}


int MidiCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}