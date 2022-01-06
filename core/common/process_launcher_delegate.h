// Copyright (c) 2014 Mumba Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_PROCESS_LAUNCHER_DELEGATE_H_
#define COMMON_PROCESS_LAUNCHER_DELEGATE_H_

#include "base/environment.h"
#include "base/files/scoped_file.h"
#include "base/process/process.h"

namespace common {

class ProcessLauncherDelegate {
public:
  virtual ~ProcessLauncherDelegate(){} 
  virtual bool ShouldSandbox();
  // Called before the default sandbox is applied. If the default policy is too
  // restrictive, the caller should set |disable_default_policy| to true and
  // apply their policy in PreSpawnTarget. |exposed_dir| is used to allow a
  //directory through the sandbox.
  virtual void PreSandbox(bool* disable_default_policy,
                          base::FilePath* exposed_dir) {}

  // Called right before spawning the process.
  virtual void PreSpawnTarget(//sandbox::TargetPolicy* policy,
                              bool* success) {}

  // Called right after the process is launched, but before its thread is run.
  virtual void PostSpawnTarget(base::ProcessHandle process) {}

  virtual base::EnvironmentMap GetEnvironment();

#if defined(OS_POSIX)
  // Return the file descriptor for the IPC channel.
  virtual base::ScopedFD TakeIpcFd() = 0;
#endif
};

}

#endif