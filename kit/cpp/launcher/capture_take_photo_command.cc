// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/capture_take_photo_command.h"

std::unique_ptr<CaptureTakePhotoCommand> CaptureTakePhotoCommand::Create() {
  return std::make_unique<CaptureTakePhotoCommand>();
}

CaptureTakePhotoCommand::CaptureTakePhotoCommand() {

}

CaptureTakePhotoCommand::~CaptureTakePhotoCommand() {

}

std::string CaptureTakePhotoCommand::GetCommandMethod() const {
  return "/mumba.Mumba/CaptureTakePhoto";
}


int CaptureTakePhotoCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  
}