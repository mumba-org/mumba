// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_APPLICATION_LAUNCH_COMMAND_H_
#define MUMBA_KIT_CPP_LAUNCHER_APPLICATION_LAUNCH_COMMAND_H_

#include <memory>

#include "launcher/command.h"
#include "launcher/launcher_daemon.h"

// The Launch command is the most unusual of the pack
// Its actually two commands 'launch' and 'close'
// where the launch is executed right away and 
// it keeps running the executable on a main loop
// once the main loop is broken somehow, it will call
// close on its cleanup

class ApplicationLaunchCommand : public Command,
                                 public LauncherDaemon::Delegate {
public:
 
 static std::unique_ptr<ApplicationLaunchCommand> Create();

 ApplicationLaunchCommand();
 ~ApplicationLaunchCommand() override;

 std::string GetCommandMethod() const override;
 int Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) override;
 void ProcessSigint(int sig) override;

private:
  void Cleanup();
  
  void OnBeforeRun() override;
  void OnAfterRun() override;

  std::unique_ptr<LauncherDaemon> daemon_;
  bool is_running_;
};

#endif