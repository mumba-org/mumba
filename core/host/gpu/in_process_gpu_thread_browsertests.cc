// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/command_line.h"
#include "base/run_loop.h"
#include "core/host/host_main_loop.h"
#include "core/host/gpu/gpu_process_host.h"
#include "content/gpu/in_process_gpu_thread.h"
#include "core/host/host_thread.h"
#include "core/common/content_switches.h"
#include "content/public/test/content_host_test.h"

namespace {

using content::InProcessGpuThread;
using content::GpuProcessHost;

class InProcessGpuTest : public content::ContentHostTest {
 public:
  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitch(switches::kInProcessGPU);
    content::ContentHostTest::SetUpCommandLine(command_line);
  }
};

void CreateGpuProcessHost() {
  GpuProcessHost::Get();
}

void WaitUntilGpuProcessHostIsCreated() {
  base::RunLoop run_loop;
  content::HostThread::PostTaskAndReply(
      content::HostThread::IO, FROM_HERE,
      base::BindOnce(&CreateGpuProcessHost), run_loop.QuitClosure());
  run_loop.Run();
}

// Reproduces the race that could give crbug.com/799002's "hang until OOM" at
// shutdown.
IN_PROC_BROWSER_TEST_F(InProcessGpuTest, NoHangAtQuickLaunchAndShutDown) {
  // ... then exit the host.
}

// Tests crbug.com/799002 but with another timing.
IN_PROC_BROWSER_TEST_F(InProcessGpuTest, NoCrashAtShutdown) {
  WaitUntilGpuProcessHostIsCreated();
  // ... then exit the host.
}

}  // namespace
