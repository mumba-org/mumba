// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/application_process.h"

#include <string.h>

#include "base/bind.h"
#include "base/feature_list.h"
#include "base/lazy_instance.h"
#include "base/sys_info.h"
#include "base/message_loop/message_loop.h"
#include "base/process/process_handle.h"
#include "base/single_thread_task_runner.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/threading/thread.h"
#include "base/threading/thread_local.h"
#include "core/shared/common/switches.h"
#include "services/service_manager/embedder/switches.h"
#include "build/build_config.h"
#include "core/shared/application/application_thread.h"

namespace application {

ApplicationProcess* g_application_process = nullptr;

namespace {

void SetV8FlagIfFeature(const base::Feature& feature, const char* v8_flag) {
  if (base::FeatureList::IsEnabled(feature)) {
    v8::V8::SetFlagsFromString(v8_flag, strlen(v8_flag));
  }
}

void SetV8FlagIfNotFeature(const base::Feature& feature, const char* v8_flag) {
  if (!base::FeatureList::IsEnabled(feature)) {
    v8::V8::SetFlagsFromString(v8_flag, strlen(v8_flag));
  }
}

void SetV8FlagIfHasSwitch(const char* switch_name, const char* v8_flag) {
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(switch_name)) {
    v8::V8::SetFlagsFromString(v8_flag, strlen(v8_flag));
  }
}  

//base::LazyInstance<base::ThreadLocalPointer<ApplicationProcess>>::DestructorAtExit
//    g_lazy_tls = LAZY_INSTANCE_INITIALIZER;

}

ApplicationProcess::ApplicationProcess(
    std::unique_ptr<base::AtExitManager> at_exit,
    base::ThreadPriority io_thread_priority,
    const std::string& task_scheduler_name,
    std::unique_ptr<base::TaskScheduler::InitParams> task_scheduler_init_params)
    : ref_count_(0),
      shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                      base::WaitableEvent::InitialState::NOT_SIGNALED),
      io_thread_("Mumba_ChildIOThread"),
      at_exit_(std::move(at_exit)),
      is_running_(false) {
  static const char experimental_extras_flag[] = "--experimental_extras";
  //DCHECK(!g_lazy_tls.Pointer()->Get());
  //g_lazy_tls.Pointer()->Set(this);

  DCHECK(!g_application_process);
  g_application_process = this;

#if DCHECK_IS_CONFIGURABLE
  // Some official builds ship with DCHECKs compiled in. Failing DCHECKs then
  // are either fatal or simply log the error, based on a feature flag.
  // Make sure V8 follows suit by setting a Dcheck handler that forwards to
  // the Chrome base logging implementation.
  v8::V8::SetDcheckErrorHandler(&V8DcheckCallbackHandler);

  if (!base::FeatureList::IsEnabled(base::kDCheckIsFatalFeature)) {
    // These V8 flags default on in this build configuration. This triggers
    // additional verification and code generation, which both slows down V8,
    // and can lead to fatal CHECKs. Turn these flags down to get something
    // closer to V8s normal performance and behavior.
    constexpr char kDisabledFlags[] =
        "--noturbo_verify "
        "--noverify_csa "
        "--noturbo_verify_allocation "
        "--nodebug_code";

    v8::V8::SetFlagsFromString(kDisabledFlags, sizeof(kDisabledFlags));
  }
#endif  // DCHECK_IS_CONFIGURABLE


  // Initialize TaskScheduler if not already done. A TaskScheduler may already
  // exist when ApplicationProcess is instantiated in the browser process or in a
  // test process.
  if (!base::TaskScheduler::GetInstance()) {
    if (task_scheduler_init_params) {
      base::TaskScheduler::Create(task_scheduler_name);
      base::TaskScheduler::GetInstance()->Start(
          *task_scheduler_init_params.get());
    } else {
      base::TaskScheduler::CreateAndStartWithDefaultParams(task_scheduler_name);
    }

    DCHECK(base::TaskScheduler::GetInstance());
    initialized_task_scheduler_ = true;
  }

  // We can't recover from failing to start the IO thread.
  base::Thread::Options thread_options(base::MessageLoop::TYPE_IO, 0);
  thread_options.priority = io_thread_priority;
#if defined(OS_ANDROID)
  // TODO(reveman): Remove this in favor of setting it explicitly for each type
  // of process.
  thread_options.priority = base::ThreadPriority::DISPLAY;
#endif
  CHECK(io_thread_.StartWithOptions(thread_options));

  if (base::SysInfo::IsLowEndDevice()) {
    std::string optimize_flag("--optimize-for-size");
    v8::V8::SetFlagsFromString(optimize_flag.c_str(),
                               static_cast<int>(optimize_flag.size()));
  }

  SetV8FlagIfHasSwitch(switches::kDisableJavaScriptHarmonyShipping,
                       "--noharmony-shipping");
  SetV8FlagIfHasSwitch(switches::kJavaScriptHarmony, "--harmony");
  SetV8FlagIfFeature(switches::kModuleScriptsDynamicImport,
                     "--harmony-dynamic-import");
  SetV8FlagIfFeature(switches::kModuleScriptsImportMetaUrl,
                     "--harmony-import-meta");
  SetV8FlagIfFeature(switches::kAsmJsToWebAssembly, "--validate-asm");
  SetV8FlagIfNotFeature(switches::kAsmJsToWebAssembly, "--no-validate-asm");
  SetV8FlagIfNotFeature(switches::kWebAssembly,
                        "--wasm-disable-structured-cloning");

  SetV8FlagIfFeature(switches::kV8VmFuture, "--future");
  SetV8FlagIfNotFeature(switches::kV8VmFuture, "--no-future");

  //SetV8FlagIfFeature(switches::kWebAssemblyBaseline, "--wasm-tier-up");
  //SetV8FlagIfNotFeature(switches::kWebAssemblyBaseline, "--no-wasm-tier-up");

  SetV8FlagIfFeature(switches::kSharedArrayBuffer,
                     "--harmony-sharedarraybuffer");
  SetV8FlagIfNotFeature(switches::kSharedArrayBuffer,
                        "--no-harmony-sharedarraybuffer");

  SetV8FlagIfNotFeature(switches::kWebAssemblyTrapHandler,
                        "--no-wasm-trap-handler");

  v8::V8::SetFlagsFromString(experimental_extras_flag, strlen(experimental_extras_flag));

#if defined(OS_LINUX) && defined(ARCH_CPU_X86_64) && !defined(OS_ANDROID)
  if (base::FeatureList::IsEnabled(switches::kWebAssemblyTrapHandler)) {
    bool use_v8_signal_handler = false;
  //  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  //  if (!command_line->HasSwitch(
  //          service_manager::switches::kDisableInProcessStackTraces)) {
  //    base::debug::SetStackDumpFirstChanceCallback(v8::V8::TryHandleSignal);
  //  } else if (!command_line->HasSwitch(switches::kEnableCrashReporter) &&
  //             !command_line->HasSwitch(
  //                 switches::kEnableCrashReporterForTesting)) {
      // If we are using WebAssembly trap handling but both Breakpad and
      // in-process stack traces are disabled then there will be no signal
      // handler. In this case, we fall back on V8's default handler
      // (https://crbug.com/798150).
      use_v8_signal_handler = true;
   // }
    // TODO(eholk): report UMA stat for how often this succeeds
    v8::V8::EnableWebAssemblyTrapHandler(use_v8_signal_handler);
  }
#endif

  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  if (command_line.HasSwitch(switches::kJavaScriptFlags)) {
    std::string flags(
        command_line.GetSwitchValueASCII(switches::kJavaScriptFlags));
    v8::V8::SetFlagsFromString(flags.c_str(), static_cast<int>(flags.size()));
  }

}

ApplicationProcess::~ApplicationProcess() {
  //DCHECK(g_lazy_tls.Pointer()->Get() == this);
  DCHECK(g_application_process == this);

  // Signal this event before destroying the child process.  That way all
  // background threads can cleanup.
  // For example, in the renderer the RenderThread instances will be able to
  // notice shutdown before the render process begins waiting for them to exit.
  shutdown_event_.Signal();

  if (main_thread_) {  // null in unittests.
    main_thread_->Shutdown();
    if (main_thread_->ShouldBeDestroyed()) {
      main_thread_.reset();
    } else {
      // Leak the main_thread_. See a comment in
      // RenderThreadImpl::ShouldBeDestroyed.
      main_thread_.release();
    }
  }

  //g_lazy_tls.Pointer()->Set(nullptr);
  g_application_process = nullptr;
  io_thread_.Stop();

  if (initialized_task_scheduler_) {
    DCHECK(base::TaskScheduler::GetInstance());
    base::TaskScheduler::GetInstance()->Shutdown();
  }
}

ApplicationThread* ApplicationProcess::main_thread() {
  return main_thread_.get();
}

void ApplicationProcess::set_main_thread(ApplicationThread* thread) {
  main_thread_.reset(thread);
}

void ApplicationProcess::AddRefProcess() {
  DCHECK(!main_thread_.get() ||  // null in unittests.
         main_thread_->main_thread_runner()->BelongsToCurrentThread());
  ref_count_++;
}

void ApplicationProcess::ReleaseProcess() {
  DCHECK(!main_thread_.get() ||  // null in unittests.
         main_thread_->main_thread_runner()->BelongsToCurrentThread());
  DCHECK(ref_count_);
  if (--ref_count_)
    return;

  if (main_thread_)  // null in unittests.
    main_thread_->OnProcessFinalRelease();
}

ApplicationProcess* ApplicationProcess::current() {
  //return g_lazy_tls.Pointer()->Get();
  return g_application_process;
}

void ApplicationProcess::Exit() {
  if (is_running_ && !quit_closure_.is_null()) {
    std::move(quit_closure_).Run();
  }
}

base::WaitableEvent* ApplicationProcess::GetShutDownEvent() {
  return &shutdown_event_;
}

std::unique_ptr<base::AtExitManager> ApplicationProcess::ReleaseAtExitManager() {
  return std::move(at_exit_);
}

}