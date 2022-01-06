// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/at_exit.h"
#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/debug/debugger.h"
#include "base/debug/leak_annotations.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/histogram_macros.h"
#include "base/run_loop.h"
#include "base/sampling_heap_profiler/sampling_heap_profiler.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/atomic_flag.h"
#include "base/time/time.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"
#include "base/trace_event/trace_event.h"
#include "rpc/grpc.h"
#include "core/common/zygote_buildflags.h"
#include "core/host/host_main_runner.h"
#include "core/host/host_main_loop.h"
#include "core/host/notification_service_impl.h"
#include "ui/base/ime/input_method_initializer.h"
#include "ui/base/resource/resource_bundle.h"
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
#include "core/host/sandbox_host_linux.h"
#endif

#include "base/path_service.h"
#include "base/base_paths.h"


namespace host {

namespace {

base::LazyInstance<base::AtomicFlag>::Leaky g_exited_main_message_loop;

}

class ShadowingAtExitManager : public base::AtExitManager {
 public:
  ShadowingAtExitManager() : base::AtExitManager(true) {}
};

HostMainRunner::HostMainRunner(): 
  initialization_started_(false),
  is_shutdown_(false)  {

}

HostMainRunner::~HostMainRunner() {
 if (initialization_started_ && !is_shutdown_)
  Shutdown();
}

int HostMainRunner::Initialize(const common::MainParams& params) {
 //git_libgit2_init();
 // init grpc library
 grpc_init();
 // init llvm

 // Init resource disk
 base::FilePath exe_path;
 base::PathService::Get(base::DIR_CURRENT, &exe_path);
 //DCHECK(r);
 base::FilePath views_pak = exe_path.Append(FILE_PATH_LITERAL("views_mus_resources.pak"));
 if (!ui::ResourceBundle::HasSharedInstance()) {
   ui::ResourceBundle::InitSharedInstanceWithPakPath(views_pak); 
 } else {
   ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(views_pak, ui::SCALE_FACTOR_100P);  
 }
 
 //base::FilePath chrome_100_pak = exe_path.Append(FILE_PATH_LITERAL("gen/mumba/app/resources/content_resources_100_percent.pak"));
 //ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(chrome_100_pak, ui::SCALE_FACTOR_100P);

 //base::FilePath chrome_200_pak = exe_path.Append(FILE_PATH_LITERAL("chrome_200_percent.pak"));
 //ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(chrome_200_pak, ui::SCALE_FACTOR_200P);

 //base::FilePath resources_pak = exe_path.Append(FILE_PATH_LITERAL("resources.pak"));
 //ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(resources_pak, ui::SCALE_FACTOR_100P);

 base::FilePath theme_resources_pak = exe_path.Append(FILE_PATH_LITERAL("gen/chrome/theme_resources_100_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(theme_resources_pak, ui::SCALE_FACTOR_100P);
 
 base::FilePath gen_resources_pak = exe_path.Append(FILE_PATH_LITERAL("gen/mumba/generated_resources_en-US.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(gen_resources_pak, ui::SCALE_FACTOR_100P);

 base::FilePath components_100_pak = exe_path.Append(FILE_PATH_LITERAL("gen/components/components_resources_100_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(components_100_pak, ui::SCALE_FACTOR_100P);

 base::FilePath components_200_pak = exe_path.Append(FILE_PATH_LITERAL("gen/components/components_resources_200_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(components_200_pak, ui::SCALE_FACTOR_200P);

 base::FilePath components_strings_pak = exe_path.Append(FILE_PATH_LITERAL("gen/lib/components/strings/components_strings_en-US.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(components_strings_pak, ui::SCALE_FACTOR_200P);

 base::FilePath resource_pak = exe_path.Append(FILE_PATH_LITERAL("gen/mumba/mumba_unscaled_resources.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(resource_pak, ui::SCALE_FACTOR_NONE);

#if defined(CONTENT_IMPLEMENTATION)
 exit_manager_.reset(new ShadowingAtExitManager());
 const auto& argv = params.command_line.argv();
 std::vector<const char *> str_arr;
 str_arr.reserve(argv.size());
 for (const auto& str : argv) {
#if defined(OS_WIN)
   str_arr.push_back(base::UTF16ToASCII(str).c_str());
#elif defined(OS_POSIX)
   str_arr.push_back(str.c_str());
#endif   
 }
 // i guess it wont work
 base::CommandLine::Init(argv.size(), argv.size() > 0 ? &str_arr[0] : nullptr);
#endif
 #if defined(OS_LINUX)
 host::SandboxHostLinux::GetInstance()->Init();
#endif
 notification_service_.reset(new NotificationServiceImpl);

 if (!initialization_started_) {
  initialization_started_ = true;

  main_loop_.reset(new HostMainLoop(params));
  main_loop_->Init();
  main_loop_->EarlyInitialization();

  // Must happen before we try to use a message loop or display any UI.
  if (!main_loop_->InitializeToolkit())
    return 1;

  main_loop_->PreMainMessageLoopStart();
  main_loop_->MainMessageLoopStart();
  main_loop_->PostMainMessageLoopStart();
  ui::InitializeInputMethod();
 }

 main_loop_->CreateStartupTasks();
 int result_code = main_loop_->result_code();
 if (result_code > 0)
  return result_code;

 // Return -1 to indicate no early termination.
 return -1;
}

int HostMainRunner::Run() {
 DCHECK(initialization_started_);
 DCHECK(!is_shutdown_);
 main_loop_->RunMainMessageLoop();
 return main_loop_->result_code();
}

void HostMainRunner::Shutdown() {
 DCHECK(initialization_started_);
 DCHECK(!is_shutdown_);
 
 main_loop_->PreShutdown();
 //LOG(INFO) << "performing clean shutdown";

 ui::ShutdownInputMethod();
 
 g_exited_main_message_loop.Get().Set();

 main_loop_->ShutdownThreadsAndCleanUp();
 main_loop_.reset(nullptr);

 notification_service_.reset(nullptr);

 is_shutdown_ = true;

 // shutdown the grpc library
 grpc_shutdown();
 //git_libgit2_shutdown();

 exit_manager_.reset(nullptr);
}

// static
bool HostMainRunner::ExitedMainMessageLoop() {
  return g_exited_main_message_loop.IsCreated() &&
         g_exited_main_message_loop.Get().IsSet();
}

}