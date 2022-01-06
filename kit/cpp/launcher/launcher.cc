// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(OS_POSIX)
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <iterator>
#include <limits>
#include <memory>
#include <set>

#include "base/at_exit.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "launcher/command.h"
#include "launcher/command_executor.h"
#include "launcher/bootstrapper.h"

static CommandExecutor* g_executor = {0};

#if defined(OS_POSIX)

void SignalHandler(int sig) {
  g_executor->ProcessSigint(sig);
}

#endif

// FIXME: process HOST, PORT and the application MANIFEST here
// the manifest and logos should be on a .pack file
// we might also put the zip file with the whole application to be installed
// locally in there or we might have a special directory for that an manage it
// like a CAS

// If we will implement a CAS BTW the .pack might also be in there

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  Bootstrapper bootstrapper;
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  base::FilePath program = cmd->GetProgram();
  std::string app_name = program.BaseName().RemoveExtension().value();
  ApplicationProfile profile(app_name);
  
  std::unique_ptr<base::MessageLoop> main_message_loop(new base::MessageLoop());
  base::PlatformThread::SetName("LaunchMain");  

  std::unique_ptr<CommandExecutor> executor(new CommandExecutor(&bootstrapper, &profile, std::move(main_message_loop)));
  g_executor = executor.get();

#if defined(OS_POSIX)
  struct sigaction sa;
  sigset_t full_sigset;
  
  sa.sa_flags = 0;
  sa.sa_handler = SignalHandler;

  if (sigemptyset(&sa.sa_mask) != 0)
    DLOG(FATAL) << "sigemptyset() failed";

  if (sigaction(SIGINT, &sa, NULL) != 0)
    DLOG(FATAL) << "sigaction() failed";

#endif

  return executor->Run(cmd);
}