// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/syslog_logging.h>

#include "arc/vm/forward-pstore/service.h"

int main(int argc, const char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::OpenLog(program_invocation_short_name, true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  base::AtExitManager at_exit;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  base::RunLoop run_loop;

  arc::Service service(run_loop.QuitClosure());
  service.Start();
  run_loop.Run();
  return 0;
}
