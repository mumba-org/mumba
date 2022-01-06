// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_SHELL_PROCESS_MAIN_RUNNER_H__
#define MUMBA_RUNTIME_SHELL_PROCESS_MAIN_RUNNER_H__

#include <string>
#include <memory>

#include "Globals.h"

#include "base/macros.h"
#include "core/common/main_params.h"
#include "core/common/process_type.h"
#include "core/shared/common/client.h"
#if defined(OS_WIN)
#include "sandbox/win/src/sandbox_types.h"
#endif

namespace base {
class AtExitManager;
}

namespace host {
class HostClient;
}

namespace utility {
class ContentUtilityClient;
}

namespace gpu {
class ContentGpuClient;
}

namespace application {
class ApplicationClient;
}

class ClientInitializer;

class ProcessMainRunner {
public:
 ProcessMainRunner();
 ~ProcessMainRunner();

 int Initialize(const common::MainParams& main_params);
 int Run();
 void Shutdown();

private:
 friend class ClientInitializer;

 void PreSandboxStartup();
 void InitializeResourceBundle();

 host::HostClient* CreateHostClient();
 gpu::ContentGpuClient* CreateGpuClient();
 utility::ContentUtilityClient* CreateUtilityClient();
 /*shell::ShellClient* CreateShellClient();
 application::ApplicationClient* CreateApplicationClient();
*/
// #if defined(USE_TCMALLOC)
//  static bool GetAllocatorWasteSizeThunk(size_t* size);
//  static void GetStatsThunk(char* buffer, int buffer_length);
//  static void ReleaseFreeMemoryThunk();
// #endif

 int RunProcess(common::ProcessType type,
  const common::MainParams& main_params);

#if defined(OS_WIN)
  sandbox::SandboxInterfaceInfo sandbox_info_;
#elif defined(OS_MACOSX)
  base::mac::ScopedNSAutoreleasePool* autorelease_pool_ = nullptr;
#endif

 base::Closure* ui_task_ = nullptr;

 std::unique_ptr<base::AtExitManager> exit_manager_;

 // True if the runner has been initialized.
 bool is_initialized_;
 // True if the runner has been shut down.
 bool is_shutdown_;

 common::Client client_;

 DISALLOW_COPY_AND_ASSIGN(ProcessMainRunner);
};

bool IsHostProcess();

#endif
