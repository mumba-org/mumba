// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/midi_send_command.h"

std::unique_ptr<MidiSendCommand> MidiSendCommand::Create() {
  return std::make_unique<MidiSendCommand>();
}

MidiSendCommand::MidiSendCommand() {

}

MidiSendCommand::~MidiSendCommand() {

}

std::string MidiSendCommand::GetCommandMethod() const {
  return "/mumba.Mumba/MidiSend";
}


int MidiSendCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}