// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_manifest_command.h"

std::unique_ptr<ApplicationManifestCommand> ApplicationManifestCommand::Create() {
  return std::make_unique<ApplicationManifestCommand>();
}

ApplicationManifestCommand::ApplicationManifestCommand() {

}
 
ApplicationManifestCommand::~ApplicationManifestCommand() {

}

std::string ApplicationManifestCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationManifest";
}

int ApplicationManifestCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {

}