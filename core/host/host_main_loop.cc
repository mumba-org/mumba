// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_main_loop.h"

#include "base/path_service.h"
#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/deferred_sequenced_task_runner.h"
#include "base/pending_task.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/sys_info.h"
#include "base/single_thread_task_runner.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/initialization_util.h"
#include "base/threading/thread.h"
#include "base/metrics/user_metrics.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/threading/thread_restrictions.h"
#include "base/system_monitor/system_monitor.h"
#include "base/power_monitor/power_monitor.h"
#include "base/power_monitor/power_monitor_device_source.h"
#include "base/files/file_util.h"
#include "base/i18n/icu_util.h"
#include "base/time/time.h"
#include "base/timer/hi_res_timer_manager.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"
#include "components/prefs/json_pref_store.h"
#include "base/environment.h"
#include "components/discardable_memory/service/discardable_shared_memory_manager.h"
#include "components/tracing/common/trace_startup_config.h"
#include "components/tracing/common/trace_to_console.h"
#include "components/tracing/common/tracing_switches.h"
#include "components/viz/common/features.h"
#include "components/viz/common/switches.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/display_embedder/compositing_mode_reporter_impl.h"
#include "components/viz/service/display_embedder/server_shared_bitmap_manager.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "net/base/network_change_notifier.h"
#include "net/socket/client_socket_factory.h"
#include "net/ssl/ssl_config_service.h"
//#include "db/db.h"
#include "storage/storage.h"
#include "core/shared/common/paths.h"
#include "core/common/result_codes.h"
#include "core/common/constants.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/service_manager_connection.h"
//#include "core/host/media/capture/audio_mirroring_manager.h"
//#include "core/host/media/media_internals.h"
//#include "core/host/memory/memory_coordinator_impl.h"
//#include "core/host/memory/swap_metrics_delegate_uma.h"
#include "core/host/service_manager/service_manager_context.h"
#include "core/host/net/host_online_state_observer.h"
#include "core/host/notification_service.h"
#include "core/host/host_subthread.h"
#include "core/host/host_service.h"
#include "core/host/gpu_data_manager_observer.h"
#include "core/host/gpu/gpu_data_manager_impl.h"
#include "core/host/gpu/gpu_process_host.h"
#include "core/host/compositor/gpu_process_transport_factory.h"
#include "core/host/compositor/surface_utils.h"
#include "core/host/compositor/viz_process_transport_factory.h"
#include "core/host/tracing/tracing_controller_impl.h"
#include "core/host/tracing/background_tracing_manager_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host.h"
#include "core/host/host_startup.h"
#include "core/host/startup_task_runner.h"
#include "core/host/ui/context_factory.h"
#include "core/host/io_thread.h"
#include "core/host/gpu/host_gpu_channel_host_factory.h"
#include "core/host/gpu/host_gpu_memory_buffer_manager.h"
#include "core/host/gpu/compositor_util.h"
#include "core/host/gpu/gpu_data_manager_impl.h"
#include "core/host/gpu/gpu_process_host.h"
//#include "core/host/gpu/gpu_transport_factory.h"
#include "core/host/gpu/shader_cache_factory.h"
#include "core/host/histogram_synchronizer.h"
#include "core/host/leveldb_wrapper_impl.h"
#include "core/host/webrtc/webrtc_internals.h"
#include "core/host/application/media/media_stream_manager.h"
#include "media/audio/audio_manager.h"
#include "media/audio/audio_system.h"
#include "media/audio/audio_thread_impl.h"
#include "media/base/media.h"
#include "media/base/user_input_monitor.h"
#include "media/media_buildflags.h"
#include "media/midi/midi_service.h"
#include "media/mojo/buildflags.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "core/shared/common/client.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/common/zygote_buildflags.h"
//#include "device/gamepad/gamepad_service.h"
#include "services/audio/public/cpp/audio_system_factory.h"
#include "services/resource_coordinator/public/cpp/memory_instrumentation/client_process_impl.h"
#include "services/resource_coordinator/public/mojom/memory_instrumentation/memory_instrumentation.mojom.h"
#include "services/resource_coordinator/public/mojom/service_constants.mojom.h"
#include "services/service_manager/runner/common/client_util.h"
#include "skia/ext/event_tracer_impl.h"
#include "skia/ext/skia_memory_dump_provider.h"
#include "sql/sql_memory_dump_provider.h"
#include "ui/base/clipboard/clipboard.h"
#include "ui/base/ui_base_features.h"
#include "ui/native_theme/native_theme.h"
#include "ui/display/display_switches.h"
#include "ui/gfx/switches.h"
#include "ui/base/material_design/material_design_controller.h"
#include "gpu/vulkan/buildflags.h"

#include "core/host/ui/dock_constrained_window_views_client.h"
#include "core/host/ui/dock_views_delegate.h"
#include "core/host/ui/layout/dock_layout_provider.h"
//#include "core/host/ui/ime_driver/ime_driver_mus.h"
#include "components/constrained_window/constrained_window_views.h"


#if defined(OS_ANDROID)
#include "base/android/jni_android.h"
#include "components/tracing/common/graphics_memory_dump_provider_android.h"
#include "core/host/android/host_startup_controller.h"
#include "core/host/android/launcher_thread.h"
#include "core/host/android/scoped_surface_request_manager.h"
#include "core/host/android/tracing_controller_android.h"
#include "core/host/media/android/host_media_player_manager.h"
#include "core/host/screen_orientation/screen_orientation_delegate_android.h"
#include "media/base/android/media_drm_bridge_client.h"
#include "ui/android/screen_android.h"
#include "ui/display/screen.h"
#include "ui/gl/gl_surface.h"
#endif

#if defined(OS_MACOSX)
#include "base/memory/memory_pressure_monitor_mac.h"
#include "core/host/cocoa/system_hotkey_helper_mac.h"
#include "core/host/mach_broker_mac.h"
//#include "core/host/application/host_compositor_view_mac.h"
#include "core/host/theme_helper_mac.h"
#include "ui/accelerated_widget_mac/window_resize_helper_mac.h"
#endif

#if defined(OS_WIN)
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include "base/memory/memory_pressure_monitor_win.h"
#include "net/base/winsock_init.h"
#include "services/service_manager/sandbox/win/sandbox_win.h"
#include "ui/base/l10n/l10n_util_win.h"
#include "ui/display/win/screen_win.h"
#endif

#if defined(OS_WIN)
#include "media/device_monitors/system_message_window_win.h"
#elif defined(OS_LINUX) && defined(USE_UDEV)
#include "media/device_monitors/device_monitor_udev.h"
#elif defined(OS_MACOSX)
#include "media/device_monitors/device_monitor_mac.h"
#endif

#if defined(OS_FUCHSIA)
#include <zircon/process.h>
#include <zircon/syscalls.h>

#include "base/fuchsia/default_job.h"
#endif  // defined(OS_FUCHSIA)

#if defined(OS_POSIX) && !defined(OS_MACOSX)
#include "core/host/sandbox_host_linux.h"
#endif

#if defined(USE_X11)
#include "gpu/config/gpu_driver_bug_workaround_type.h"
#include "ui/base/x/x11_util_internal.h"  // nogncheck
#include "ui/gfx/x/x11_connection.h"  // nogncheck
#include "ui/gfx/x/x11_types.h"  // nogncheck
#include "ui/events/devices/x11/touch_factory_x11.h"
#include "core/host/ui/libgtkui/gtk_ui.h"
#endif

#if defined(USE_AURA) || defined(OS_MACOSX)
#include "core/host/compositor/image_transport_factory.h"
#endif

#if defined(USE_AURA)
#include "services/ui/public/cpp/gpu/gpu.h"  // nogncheck
#include "services/ui/public/cpp/input_devices/input_device_client.h"
#include "services/ui/public/interfaces/constants.mojom.h"
#include "services/ui/public/interfaces/input_devices/input_device_server.mojom.h"
#include "ui/aura/env.h"
#include "ui/display/screen.h"
#include "ui/views/mus/mus_client.h"
#include "ui/views/widget/desktop_aura/desktop_screen.h"
#include "ui/wm/core/wm_state.h"
#if defined(USE_X11)
#include "ui/views/linux_ui/linux_ui.h"
#include "ui/views/widget/desktop_aura/x11_desktop_handler.h"
#endif
#endif

#if defined(OS_POSIX)
#include <signal.h>
#endif // OS_POSIX

#if BUILDFLAG(ENABLE_VULKAN)
#include "gpu/vulkan/vulkan_implementation.h"
#endif

// initialization for stellar ledger
#include "third_party/libsodium/src/libsodium/include/sodium/core.h"

namespace host {

 #if defined(USE_X11) 

class X11DesktopHandlerObserver : public views::X11DesktopHandlerObserver {
 public:
  X11DesktopHandlerObserver() {}
  ~X11DesktopHandlerObserver() override {}

  // Overridden from views::X11DesktopHandlerObserver.
  void OnWorkspaceChanged(const std::string& new_workspace) override {
    DLOG(INFO) << "X11 workspace changed";
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(X11DesktopHandlerObserver);
};

#endif

namespace {

#if defined(OS_LINUX)
ui::NativeTheme* GetNativeThemeForWindow(aura::Window* window) {
 if (!window)
     return nullptr;

   return ui::NativeTheme::GetInstanceForNativeUi();
}
#endif

#if defined(USE_AURA)
bool ShouldCreateWMState() {
#if defined(OS_CHROMEOS)
  return chromeos::GetAshConfig() != ash::Config::MUS;
#else
  return true;
#endif
}
#endif

void OnStoppedStartupTracing(const base::FilePath& trace_file) {
  VLOG(0) << "Completed startup tracing to " << trace_file.value();
}

 // NOINLINE void ResetThread_FILE(std::unique_ptr<HostSubThread> thread) {
 //  volatile int inhibit_comdat = __LINE__;
 //  ALLOW_UNUSED_LOCAL(inhibit_comdat);
 //  thread.reset();
 // }

 // NOINLINE void ResetThread_DB(std::unique_ptr<HostSubThread> thread) {
 //  volatile int inhibit_comdat = __LINE__;
 //  ALLOW_UNUSED_LOCAL(inhibit_comdat);
 //  thread.reset();
 // }

 // NOINLINE void ResetThread_Rpc(std::unique_ptr<HostSubThread> thread) {
 //  volatile int inhibit_comdat = __LINE__;
 //  ALLOW_UNUSED_LOCAL(inhibit_comdat);
 //  thread.reset();
 // }

 // NOINLINE void ResetThread_DISPATCHER(std::unique_ptr<HostSubThread> thread) {
 //  volatile int inhibit_comdat = __LINE__;
 //  ALLOW_UNUSED_LOCAL(inhibit_comdat);
 //  thread.reset();
 // }

 NOINLINE void ResetThread_PROCESS_LAUNCHER(
  std::unique_ptr<HostSubThread> thread) {
  volatile int inhibit_comdat = __LINE__;
  ALLOW_UNUSED_LOCAL(inhibit_comdat);
  thread.reset();
 }

 NOINLINE void ResetThread_IO(std::unique_ptr<HostSubThread> thread) {
  volatile int inhibit_comdat = __LINE__;
  ALLOW_UNUSED_LOCAL(inhibit_comdat);
  thread.reset();
 }

 // NOINLINE void ResetThread_NOTIFICATION(std::unique_ptr<HostSubThread> thread) {
 //  volatile int inhibit_comdat = __LINE__;
 //  ALLOW_UNUSED_LOCAL(inhibit_comdat);
 //  thread.reset();
 // }

 // NOINLINE void ResetThread_WATCHDOG(std::unique_ptr<HostSubThread> thread) {
 //  volatile int inhibit_comdat = __LINE__;
 //  ALLOW_UNUSED_LOCAL(inhibit_comdat);
 //  thread.reset();
 // }

 base::FilePath GetStartupRootPath() {
  base::FilePath root_dir;
  PathService::Get(common::DIR_ROOT, &root_dir);
  return root_dir;
 }

 bool IsFirstRun() {
  base::FilePath path;
  common::GetDefaultRootDirectory(&path);

  if (!base::DirectoryExists(path))
   return true;

  return false;
 }

 bool ProcessSingletonNotificationCallback(
  const base::CommandLine& command_line,
  const base::FilePath& current_directory) {
  // Drop the request if the host process is already in shutdown path.
  std::string result; // disabled for now
  if (!Host::Instance())
   return false;

  base::FilePath startup_root_dir = GetStartupRootPath();

  HostStartup::ProcessCommandLineAlreadyRunning(
   command_line, current_directory, startup_root_dir, &result);

  return true;
 }

#if defined(OS_FUCHSIA)
// Create and register the job which will contain all child processes
// of the host process as well as their descendents.
void InitDefaultJob() {
  base::ScopedZxHandle handle;
  zx_status_t result = zx_job_create(zx_job_default(), 0, handle.receive());
  CHECK_EQ(ZX_OK, result) << "zx_job_create(job): "
                          << zx_status_get_string(result);
  base::SetDefaultJob(std::move(handle));
}
#endif  // defined(OS_FUCHSIA)

} // namespace


// #if defined(OS_POSIX) && !defined(OS_IOS)
// static void SetHostSignalHandlers() {
//  // Sanitise our signal handling state. Signals that were ignored by our
//  // parent will also be ignored by us. We also inherit our parent's sigmask.
//  sigset_t empty_signal_set;
//  CHECK(0 == sigemptyset(&empty_signal_set));
//  CHECK(0 == sigprocmask(SIG_SETMASK, &empty_signal_set, NULL));

//  struct sigaction sigint;
//  memset(&sigint, 0, sizeof(sigint));
//  sigint.sa_handler = &HostMainLoop::ProcessSignal;
  
//  struct sigaction sigterm;
//  memset(&sigterm, 0, sizeof(sigterm));
//  sigterm.sa_handler = &HostMainLoop::ProcessSignal;
  
//  CHECK(0 == sigaction(SIGINT, &sigint, NULL));
//  CHECK(0 == sigaction(SIGTERM, &sigterm, NULL));
// }
// #endif // defined(OS_POSIX) && !defined(OS_IOS) 


#if defined(USE_X11)
namespace internal {

// Forwards GPUInfo updates to ui::XVisualManager
class GpuDataManagerVisualProxy : public GpuDataManagerObserver {
 public:
  explicit GpuDataManagerVisualProxy(GpuDataManagerImpl* gpu_data_manager)
      : gpu_data_manager_(gpu_data_manager) {
    gpu_data_manager_->AddObserver(this);
  }

  ~GpuDataManagerVisualProxy() override {
    gpu_data_manager_->RemoveObserver(this);
  }

  void OnGpuInfoUpdate() override {
    if (base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kHeadless))
      return;
    gpu::GPUInfo gpu_info = gpu_data_manager_->GetGPUInfo();
    if (!ui::XVisualManager::GetInstance()->OnGPUInfoChanged(
            gpu_info.software_rendering ||
                !gpu_data_manager_->GpuAccessAllowed(nullptr),
            gpu_info.system_visual, gpu_info.rgba_visual)) {
      // The GPU process sent back bad visuals, which should never happen.
      auto* gpu_process_host = GpuProcessHost::Get(
          GpuProcessHost::GPU_PROCESS_KIND_SANDBOXED, false);
      if (gpu_process_host)
        gpu_process_host->ForceShutdown();
    }
  }

 private:
  GpuDataManagerImpl* gpu_data_manager_;

  DISALLOW_COPY_AND_ASSIGN(GpuDataManagerVisualProxy);
};

}  // namespace internal
#endif


HostMainLoop* g_current_host_main_loop = NULL;

// static 
HostMainLoop* HostMainLoop::GetInstance() {
 //DCHECK(HostThread::CurrentlyOn(HostThread::UI));
 return g_current_host_main_loop;
}

HostMainLoop::HostMainLoop(const common::MainParams& parameters) : parameters_(parameters),
  parsed_command_line_(parameters.command_line),
  result_code_(common::RESULT_CODE_NORMAL_EXIT),
  created_threads_(false),
  notify_result_(ProcessSingleton::PROCESS_NONE),
  should_run_(true),
  is_first_run_(false),
  weak_factory_(this) {

 const int num_cores = base::SysInfo::NumberOfProcessors();   
 
 DCHECK(!g_current_host_main_loop);
 g_current_host_main_loop = this;

 //base::TaskScheduler::Create("Host");
 //base::TaskScheduler::CreateAndStartWithDefaultParams("Host");
 constexpr int kBackgroundMaxThreads = 4;
 constexpr int kBackgroundBlockingMaxThreads = 4;
 const int kForegroundMaxThreads = std::max(12, num_cores - 1);
 const int kForegroundBlockingMaxThreads = std::max(14, num_cores - 1);

 //constexpr TimeDelta kSuggestedReclaimTime = TimeDelta::FromSeconds(30);
 constexpr base::TimeDelta kSuggestedReclaimTime = base::TimeDelta::FromSeconds(15);
 base::TaskScheduler::InitParams init_params{{kBackgroundMaxThreads, kSuggestedReclaimTime},
    {kBackgroundBlockingMaxThreads, kSuggestedReclaimTime},
    {kForegroundMaxThreads, kSuggestedReclaimTime},
    {kForegroundBlockingMaxThreads, kSuggestedReclaimTime}};
  
 base::TaskScheduler::Create("HostProcess");
 base::TaskScheduler::GetInstance()->Start(init_params);
}

HostMainLoop::~HostMainLoop() {
 DCHECK_EQ(this, g_current_host_main_loop);
 ui::Clipboard::DestroyClipboardForCurrentThread();
#if defined(OS_LINUX)
 if (views::X11DesktopHandler::get_dont_create())
    views::X11DesktopHandler::get_dont_create()->RemoveObserver(x_desktop_handler_observer_.get());
#endif
 constrained_window::SetConstrainedWindowViewsClient(nullptr);
 g_current_host_main_loop = NULL;
}

gpu::GpuChannelEstablishFactory* HostMainLoop::gpu_channel_establish_factory() const {
  return HostGpuChannelHostFactory::instance();
}

#if defined(OS_ANDROID)
void HostMainLoop::SynchronouslyFlushStartupTasks() {
  startup_task_runner_->RunAllTasksNow();
}
#endif  // OS_ANDROID

base::SequencedTaskRunner* HostMainLoop::audio_service_runner() {
  return audio_service_runner_.get();
}

#if !defined(OS_ANDROID)
viz::FrameSinkManagerImpl* HostMainLoop::GetFrameSinkManager() const {
  return frame_sink_manager_impl_.get();
}
#endif

void HostMainLoop::GetCompositingModeReporter(
    viz::mojom::CompositingModeReporterRequest request) {
#if defined(OS_ANDROID)
  // Android doesn't support non-gpu compositing modes, and doesn't make a
  // CompositingModeReporter.
  return;
#else
  if (features::IsMusEnabled()) {
    // Mus == ChromeOS, which doesn't support software compositing, so no need
    // to report compositing mode.
    return;
  }

  compositing_mode_reporter_impl_->BindRequest(std::move(request));
#endif
}

void HostMainLoop::Init() {

 common::RegisterPathProvider();

 base::i18n::InitializeICU();

 //git_libgit2_init();
 //storage::Init();

 is_first_run_ = IsFirstRun();

 root_dir_ = GetStartupRootPath();
}

void HostMainLoop::EarlyInitialization() {
#if defined(OS_LINUX)
  views::LinuxUI* gtk2_ui = BuildGtkUi();
  gtk2_ui->SetNativeThemeOverride(base::Bind(&GetNativeThemeForWindow));
  views::LinuxUI::SetInstance(gtk2_ui);
#endif  

#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  // The initialization of the sandbox host ends up with forking the Zygote
  // process and requires no thread been forked. The initialization has happened
  // by now since a thread to start the ServiceManager has been created
  // before the host main loop starts.
  DCHECK(SandboxHostLinux::GetInstance()->IsInitialized());
#endif

//#if defined(USE_X11)
  //if (UsingInProcessGpu()) {
  //  if (!gfx::InitializeThreadedX11()) {
  //    LOG(ERROR) << "Failed to put Xlib into threaded mode.";
  //  }
  //}
//#endif

const base::CommandLine* command_line =
        base::CommandLine::ForCurrentProcess();
    
    base::FeatureList::InitializeInstance(
        command_line->GetSwitchValueASCII(switches::kEnableFeatures),
        command_line->GetSwitchValueASCII(switches::kDisableFeatures));

#if defined(OS_WIN)
 net::EnsureWinsockInit();
#endif

#if defined(OS_FUCHSIA)
 InitDefaultJob();
#endif
 //const base::CommandLine::StringVector& argv = parsed_command_line_.argv();
 //char*** null_args = {};
 //db::Init(0, null_args);
//#if !defined(USE_OPENSSL)
// // We want to be sure to init NSPR on the main thread.
// crypto::EnsureNSPRInit();
//#endif  // !defined(USE_OPENSSL)
}

void HostMainLoop::MainMessageLoopStart() {
 if (!base::MessageLoop::current())
  main_message_loop_.reset(new base::MessageLoopForUI);

 InitializeMainThread();

//  scoped_refptr<base::SequencedTaskRunner> local_state_task_runner =
//   JsonPrefStore::GetTaskRunnerForFile(
//   base::FilePath(constants::kLocalStorePoolName),
//   HostThread::GetBlockingPool());
 //host_.reset(new Host(root_dir_, local_state_task_runner.get(), parameters_, is_first_run_));
 host_.reset(new Host(weak_factory_.GetWeakPtr(), root_dir_, parameters_, is_first_run_));
}

void HostMainLoop::CreateStartupTasks() {
 if (!startup_task_runner_.get()) {

  startup_task_runner_.reset(new StartupTaskRunner(
   base::Callback<void(int)>(),
   base::ThreadTaskRunnerHandle::Get()));

  StartupTask pre_create_threads =
   base::Bind(&HostMainLoop::PreCreateThreads, base::Unretained(this));
  startup_task_runner_->AddTask(pre_create_threads);

  StartupTask create_threads =
   base::Bind(&HostMainLoop::CreateThreads, base::Unretained(this));
  startup_task_runner_->AddTask(create_threads);

  StartupTask host_thread_started = base::Bind(
   &HostMainLoop::HostThreadsStarted, base::Unretained(this));
  startup_task_runner_->AddTask(host_thread_started);

  StartupTask pre_main_message_loop_run = base::Bind(
   &HostMainLoop::PreMainMessageLoopRun, base::Unretained(this));
  startup_task_runner_->AddTask(pre_main_message_loop_run);
 }

 startup_task_runner_->RunAllTasksNow();
}

void HostMainLoop::RunMainMessageLoop() {
 //DCHECK(base::MessageLoopForIO::IsCurrent());
 DCHECK(base::MessageLoopForUI::IsCurrent());

 if (should_run_) {
  //if (parameters_.ui_task)
   //base::MessageLoopForIO::current()->PostTask(FROM_HERE,
   //*parameters_.ui_task);
  //base::RunLoop run_loop;
  //run_loop.Run();
  host_->set_inside_runloop(true);
  //base::MessageLoopForIO::current()->Run();
  //main_loop_.Run();
  base::RunLoop run_loop;
  loop_quit_ = run_loop.QuitClosure();

  run_loop.Run();
  host_->set_inside_runloop(false);
 }

 result_code_ = 0;
}

void HostMainLoop::QuitMainMessageLoop() {
  if (!loop_quit_.is_null()) {
    std::move(loop_quit_).Run();
  }
}

void HostMainLoop::ShutdownThreadsAndCleanUp() {
 if (!created_threads_)
  return;

 //system_stats_monitor_.reset();

  // Request shutdown to clean up allocated resources on the IO thread.
  if (midi_service_) {
    TRACE_EVENT0("shutdown", "HostMainLoop::Subsystem:MidiService");
    midi_service_->Shutdown();
  }

  //memory_pressure_monitor_.reset();

#if defined(OS_MACOSX)
  HostCompositorMac::DisableRecyclingForShutdown();
#endif

#if !defined(OS_ANDROID)
  host_frame_sink_manager_.reset();
  frame_sink_manager_impl_.reset();
  compositing_mode_reporter_impl_.reset();
#endif

#if defined(OS_WIN)
  system_message_window_.reset();
#elif defined(OS_MACOSX)
  device_monitor_mac_.reset();
#endif

if (HostGpuChannelHostFactory::instance()) {
    HostGpuChannelHostFactory::instance()->CloseChannel();
}

// Shutdown the Service Manager and IPC.
service_manager_context_.reset();
mojo_ipc_support_.reset();

 if (notify_result_ == ProcessSingleton::PROCESS_NONE)
  process_singleton_->Cleanup();

 host_->StartTearDown();

 // Teardown may start in PostMainMessageLoopRun, and during teardown we
 // need to be able to perform IO.
 base::ThreadRestrictions::SetIOAllowed(true);
 HostThread::PostTask(
  HostThread::IO, FROM_HERE,
  base::Bind(base::IgnoreResult(&base::ThreadRestrictions::SetIOAllowed),
  true));


 //host_->PostMainMessageLoopRun(notify_result_ == ProcessSingleton::PROCESS_NONE);
 host_->PostMainMessageLoopRun();

 for (size_t thread_id = HostThread::MAX - 1;
  thread_id >= (HostThread::UI + 1);
  --thread_id) {
  // Find the thread object we want to stop. Looping over all valid
  // HostThread IDs and DCHECKing on a missing case in the switch
  // statement helps avoid a mismatch between this code and the
  // HostThread::ID enumeration.
  //
  // The destruction order is the reverse order of occurrence in the
  // HostThread::ID list. The rationale for the order is as
  // follows (need to be filled in a bit):
  //
  //
  //
  // - The PROCESS_LAUNCHER thread must be stopped after IO in case
  //   the IO thread posted a task to terminate a process on the
  //   process launcher thread.
  //
  // - (Not sure why DB stops last.)
  switch (thread_id) {
  case HostThread::IO: {
   ResetThread_IO(std::move(io_thread_));
   break;
  }
  // case HostThread::NOTIFICATION: {
  //  ResetThread_NOTIFICATION(std::move(notification_thread_));
  //  break;
  // }
  // case HostThread::DISPATCHER: {
  //  ResetThread_DISPATCHER(std::move(dispatcher_thread_));
  //  break;
  // }
  // case HostThread::DB: {
  //  ResetThread_DB(std::move(db_thread_));
  //  break;
  // }
  // case HostThread::Rpc: {
  //  ResetThread_Rpc(std::move(rpc_thread_));
  //  break;
  // }
  // case HostThread::WATCHDOG: {
  //  ResetThread_WATCHDOG(std::move(watchdog_thread_));
  //  break;
  // }
  // case HostThread::FILE: {
  //  ResetThread_FILE(std::move(file_thread_));
  //  break;
  // }
  case HostThread::PROCESS_LAUNCHER: {
   ResetThread_PROCESS_LAUNCHER(std::move(process_launcher_thread_));
   break;
  }
  case HostThread::UI:
  case HostThread::MAX:
  default:
   NOTREACHED();
   break;
  }
 }

 
 //HostThread::ShutdownThreadPool();

 {
  TRACE_EVENT0("shutdown", "HostMainLoop::Subsystem:TaskScheduler");
  base::TaskScheduler::GetInstance()->Shutdown();
 }

  {
    TRACE_EVENT0("shutdown", "HostMainLoop::Subsystem:GPUChannelFactory");
    if (HostGpuChannelHostFactory::instance()) {
      HostGpuChannelHostFactory::Terminate();
    }
  }

  // Must happen after the I/O thread is shutdown since this class lives on the
  // I/O thread and isn't threadsafe.
  //{
   //  TRACE_EVENT0("shutdown", "HostMainLoop::Subsystem:GamepadService");
  //  device::GamepadService::GetInstance()->Terminate();
  //}

  {
    TRACE_EVENT0("shutdown", "HostMainLoop::Subsystem:AudioMan");
    if (audio_manager_ && !audio_manager_->Shutdown()) {
      // Intentionally leak AudioManager if shutdown failed.
      // We might run into various CHECK(s) in AudioManager destructor.
      ignore_result(audio_manager_.release());
      // |user_input_monitor_| may be in use by stray streams in case
      // AudioManager shutdown failed.
      ignore_result(user_input_monitor_.release());
    }

    // Leaking AudioSystem: we cannot correctly destroy it since Audio service
    // connection in there is bound to IO thread.
    ignore_result(audio_system_.release());
  }

 host_->PostDestroyThreads();
 host_.release();

 weak_factory_.InvalidateWeakPtrs();

 delete g_host;

 process_singleton_.reset();

 //git_libgit2_shutdown();
}

void HostMainLoop::InitializeMojo() {
  if (!parsed_command_line_.HasSwitch(switches::kSingleProcess)) {
    // Disallow mojo sync calls in the browser process. Note that we allow sync
    // calls in single-process mode since renderer IPCs are made from a browser
    // thread.
    bool sync_call_allowed = false;
    MojoResult result = mojo::edk::SetProperty(
        MOJO_PROPERTY_TYPE_SYNC_CALL_ALLOWED, &sync_call_allowed);
    DCHECK_EQ(MOJO_RESULT_OK, result);
  }

  mojo_ipc_support_.reset(new mojo::edk::ScopedIPCSupport(
      HostThread::GetTaskRunnerForThread(HostThread::IO),
      mojo::edk::ScopedIPCSupport::ShutdownPolicy::FAST));

  service_manager_context_.reset(new ServiceManagerContext);
#if defined(OS_MACOSX)
  mojo::edk::SetMachPortProvider(MachBroker::GetInstance());
#endif  // defined(OS_MACOSX)
  common::GetClient()->OnServiceManagerConnected(
      common::ServiceManagerConnection::GetForProcess());

  tracing_controller_ = std::make_unique<TracingControllerImpl>();
  BackgroundTracingManagerImpl::GetInstance()
      ->AddMetadataGeneratorFunction();

  // Registers the browser process as a memory-instrumentation client, so
  // that data for the browser process will be available in memory dumps.
  ::service_manager::Connector* connector =
      common::ServiceManagerConnection::GetForProcess()->GetConnector();
  memory_instrumentation::ClientProcessImpl::Config config(
      connector, resource_coordinator::mojom::kServiceName,
      memory_instrumentation::mojom::ProcessType::BROWSER);
  memory_instrumentation::ClientProcessImpl::CreateInstance(config);

  // Start startup tracing through TracingController's interface. TraceLog has
  // been enabled in content_main_runner where threads are not available. Now We
  // need to start tracing for all other tracing agents, which require threads.
  auto* trace_startup_config = tracing::TraceStartupConfig::GetInstance();
  if (trace_startup_config->IsEnabled()) {
    // This checks kTraceConfigFile switch.
    TracingController::GetInstance()->StartTracing(
        trace_startup_config->GetTraceConfig(),
        TracingController::StartTracingDoneCallback());
  } else if (parsed_command_line_.HasSwitch(switches::kTraceToConsole)) {
    TracingController::GetInstance()->StartTracing(
        tracing::GetConfigForTraceToConsole(),
        TracingController::StartTracingDoneCallback());
  }
  // Start tracing to a file for certain duration if needed. Only do this after
  // starting the main message loop to avoid calling
  // MessagePumpForUI::ScheduleWork() before MessagePumpForUI::Start() as it
  // will crash the browser.
  if (trace_startup_config->IsTracingStartupForDuration()) {
    TRACE_EVENT0("startup", "BrowserMainLoop::InitStartupTracingForDuration");
    InitStartupTracingForDuration();
  }

 // if (parts_) {
  //  parts_->ServiceManagerConnectionStarted(
  //      ServiceManagerConnection::GetForProcess());
  //}
  ServiceManagerConnectionStarted(common::ServiceManagerConnection::GetForProcess());
}

void HostMainLoop::ServiceManagerConnectionStarted(common::ServiceManagerConnection* connection) {
    // Initializing the connector asynchronously configures the Connector on the
    // IO thread. This needs to be done before StartService() is called or
    // ChromeService::BindConnector() can race with ChromeService::OnStart().
    HostService::GetInstance()->InitConnector();

    connection->GetConnector()->StartService(
        service_manager::Identity(common::mojom::kHostServiceName));
        //service_manager::Identity(chrome::mojom::kServiceName));

    #if defined(USE_AURA)
  if (aura::Env::GetInstance()->mode() == aura::Env::Mode::LOCAL)
    return;

#if defined(OS_CHROMEOS)
  // Start up the window service and the ash system UI service.
  if (chromeos::GetAshConfig() == ash::Config::MASH) {
    connection->GetConnector()->StartService(
        service_manager::Identity(ui::mojom::kServiceName));
    connection->GetConnector()->StartService(
        service_manager::Identity(ash::mojom::kServiceName));
  }
#endif

  input_device_client_ = std::make_unique<ui::InputDeviceClient>();
  ui::mojom::InputDeviceServerPtr server;
  connection->GetConnector()->BindInterface(ui::mojom::kServiceName, &server);
  input_device_client_->Connect(std::move(server));

#if defined(OS_CHROMEOS)
  if (chromeos::GetAshConfig() != ash::Config::MASH)
    return;
#endif

  // WMState is owned as a member, so don't have MusClient create it.
  const bool create_wm_state = false;
  mus_client_ = std::make_unique<views::MusClient>(
      connection->GetConnector(), service_manager::Identity(),
      HostThread::GetTaskRunnerForThread(
          HostThread::IO),
      create_wm_state);
#endif  // defined(USE_AURA)
}


void HostMainLoop::CreateAudioManager() {
  DCHECK(!audio_manager_);

  //audio_manager_ = GetClient()->host()->CreateAudioManager(
  //    MediaInternals::GetInstance());
  // TODO(http://crbug/834666): Do not initialize |audio_manager_| if
  // features::kAudioServiceOutOfProcess is enabled.
  if (!audio_manager_) {
    audio_manager_ =
        // TEMPORARY 
        media::AudioManager::CreateForTesting(std::make_unique<media::AudioThreadImpl>()//,
                                    );//MediaInternals::GetInstance());
  }
  CHECK(audio_manager_);

  //AudioMirroringManager* const mirroring_manager =
  //    AudioMirroringManager::GetInstance();
  //audio_manager_->SetDiverterCallbacks(
  //    mirroring_manager->GetAddDiverterCallback(),
  //    mirroring_manager->GetRemoveDiverterCallback());

  TRACE_EVENT_INSTANT0("startup", "Starting Audio service task runner",
                       TRACE_EVENT_SCOPE_THREAD);
  audio_service_runner_->StartWithTaskRunner(audio_manager_->GetTaskRunner());

  audio_system_ = audio::CreateAudioSystem(
      common::ServiceManagerConnection::GetForProcess()
          ->GetConnector()
          ->Clone());
  CHECK(audio_system_);
}

void HostMainLoop::InitializeMainThread() {
 const char* kThreadName = "MumbaHostUI";
 base::PlatformThread::SetName(kThreadName);
// if (main_message_loop_)
//  main_message_loop_->set_thread_name(kThreadName);

 // Register the main thread by instantiating it, but don't call any methods.
 main_thread_.reset(
  new HostThread(HostThread::UI, base::ThreadTaskRunnerHandle::Get()));
}

int HostMainLoop::PreCreateThreads() {
 InitializeMemoryManagementComponent();
 #if defined(OS_MACOSX)
  // The WindowResizeHelper allows the UI thread to wait on specific renderer
  // and GPU messages from the IO thread. Initializing it before the IO thread
  // starts ensures the affected IO thread messages always have somewhere to go.
  ui::WindowResizeHelperMac::Get()->Init(base::ThreadTaskRunnerHandle::Get());
#endif
  // 1) Need to initialize in-process GpuDataManager before creating threads.
  // It's unsafe to append the gpu command line switches to the global
  // CommandLine::ForCurrentProcess object after threads are created.
  // 2) Must be after parts_->PreCreateThreads to pick up chrome://flags.
  GpuDataManagerImpl::GetInstance();

#if defined(USE_X11)
  gpu_data_manager_visual_proxy_.reset(new internal::GpuDataManagerVisualProxy(
      GpuDataManagerImpl::GetInstance()));
#endif

  // Initialize origins that are whitelisted for process isolation.  Must be
  // done after base::FeatureList is initialized, but before any navigations
  // can happen.
  //ChildProcessSecurityPolicyImpl* policy =
  //    ChildProcessSecurityPolicyImpl::GetInstance();
  //policy->AddIsolatedOrigins(SiteIsolationPolicy::GetIsolatedOrigins());

  // Record metrics about which site isolation flags have been turned on.
  //SiteIsolationPolicy::StartRecordingSiteIsolationFlagUsage();  

 process_singleton_.reset(new ProcessSingleton(
  root_dir_, base::Bind(&ProcessSingletonNotificationCallback)));

#if defined(USE_AURA) && !defined(OS_CHROMEOS) && !defined(USE_OZONE)
  // The screen may have already been set in test initialization.
  if (!display::Screen::GetScreen())
    display::Screen::SetScreenInstance(views::CreateDesktopScreen());
#endif

#if defined(OS_LINUX)
  views::LinuxUI::instance()->UpdateDeviceScaleFactor();
#endif
  ui::MaterialDesignController::Initialize();

  if (!views::LayoutProvider::Get())
    layout_provider_ = DockLayoutProvider::CreateLayoutProvider();

#if defined(OS_LINUX)
  x_desktop_handler_observer_ = std::make_unique<X11DesktopHandlerObserver>();
  views::X11DesktopHandler::get()->AddObserver(x_desktop_handler_observer_.get());
#endif

  // initialization libsodium here (necessary for stellar ledger)
  if (sodium_init() != 0){
    LOG(ERROR) << "could not initialize crypto (libsodium)";
    return 1;
  }
  
  host_->PreCreateThreads();

  return 0;
}

int HostMainLoop::CreateThreads() {

 base::Thread::Options default_options;
 base::Thread::Options io_message_loop_options;
 io_message_loop_options.message_loop_type = base::MessageLoop::TYPE_IO;
 base::Thread::Options ui_message_loop_options;
 ui_message_loop_options.message_loop_type = base::MessageLoop::TYPE_UI;
 // Start threads in the order they occur in the HostThread::ID
 // enumeration, except for HostThread::UI which is the main
 // thread.
 //
 // Must be size_t so we can increment it.
 for (size_t thread_id = HostThread::UI + 1;
  thread_id < HostThread::MAX;
  ++thread_id) {
  std::unique_ptr<HostSubThread>* thread_to_start = NULL;
  base::Thread::Options* options = &default_options;

  switch (thread_id) {
   case HostThread::PROCESS_LAUNCHER:
    thread_to_start = &process_launcher_thread_;
    options->timer_slack = base::TIMER_SLACK_MAXIMUM;
    break;
//   case HostThread::FILE:
//    thread_to_start = &file_thread_;
// #if defined(OS_WIN)
//    // On Windows, the FILE thread needs to be have a UI message loop
//    // which pumps messages in such a way that Google Update can
//    // communicate back to us.
//    options = &ui_message_loop_options;
// #else
//    options = &io_message_loop_options;
// #endif
//    options->timer_slack = base::TIMER_SLACK_MAXIMUM;
//    break; 
//   case HostThread::DB:
//    thread_to_start = &db_thread_;
//    options = &io_message_loop_options;
//    break;
//   case HostThread::Rpc:
//    thread_to_start = &rpc_thread_;
//    options = &io_message_loop_options;
//    break; 
//   case HostThread::WATCHDOG:
//    thread_to_start = &watchdog_thread_;
//    options = &io_message_loop_options;
//    break; 
//   case HostThread::DISPATCHER:
//    thread_to_start = &dispatcher_thread_;
//    options = &io_message_loop_options;
//    break;
//   case HostThread::NOTIFICATION:
//    thread_to_start = &notification_thread_;
//    options = &io_message_loop_options;
//    options->timer_slack = base::TIMER_SLACK_MAXIMUM;
//    break; 
  case HostThread::IO:
   thread_to_start = &io_thread_;
   options = &io_message_loop_options;
   options->timer_slack = base::TIMER_SLACK_MAXIMUM;
   break;
  case HostThread::UI:
  case HostThread::MAX:
  default:
   NOTREACHED();
   break;
  }
  HostThread::ID id = static_cast<HostThread::ID>(thread_id);
  if (thread_to_start) {
   (*thread_to_start).reset(new HostSubThread(id));
   if (!(*thread_to_start)->StartWithOptions(*options)) {
    LOG(FATAL) << "Failed to start the host thread: id == " << id;
   }
  }
  else {
   NOTREACHED();
  }
 }
 created_threads_ = true;
 return result_code_;
}

int HostMainLoop::HostThreadsStarted() {
  audio_service_runner_ =
      base::MakeRefCounted<base::DeferredSequencedTaskRunner>();

  // Bring up Mojo IPC and the embedded Service Manager as early as possible.
  // Initializaing mojo requires the IO thread to have been initialized first,
  // so this cannot happen any earlier than now.
  InitializeMojo();
#if BUILDFLAG(ENABLE_MUS)
  if (features::IsMusEnabled()) {
    base::CommandLine::ForCurrentProcess()->AppendSwitch(
        switches::kEnableSurfaceSynchronization);
  }
#endif

  HistogramSynchronizer::GetInstance();
#if defined(OS_ANDROID) || defined(OS_CHROMEOS)
  // Up the priority of the UI thread.
  base::PlatformThread::SetCurrentThreadPriority(base::ThreadPriority::DISPLAY);
#endif

#if BUILDFLAG(ENABLE_VULKAN)
  if (parsed_command_line_.HasSwitch(switches::kEnableVulkan))
    gpu::InitializeVulkan();
#endif

  // Initialize the GPU shader cache. This needs to be initialized before
  // HostGpuChannelHostFactory below, since that depends on an initialized
  // ShaderCacheFactory.
  InitShaderCacheFactorySingleton(
      HostThread::GetTaskRunnerForThread(HostThread::IO));

  // If mus is not hosting viz, then the host must.
  bool host_is_viz_host = true;//!base::FeatureList::IsEnabled(::features::kMash);

  bool always_uses_gpu = true;
  bool established_gpu_channel = false;
#if defined(OS_ANDROID)
  // TODO(crbug.com/439322): This should be set to |true|.
  established_gpu_channel = false;
  always_uses_gpu = ShouldStartGpuProcessOnHostStartup();
  HostGpuChannelHostFactory::Initialize(established_gpu_channel);
#else
  established_gpu_channel = true;
  if (parsed_command_line_.HasSwitch(switches::kDisableGpu) ||
      parsed_command_line_.HasSwitch(switches::kDisableGpuCompositing) ||
      //parsed_command_line_.HasSwitch(switches::kDisableGpuEarlyInit) ||
      !host_is_viz_host) {
    established_gpu_channel = always_uses_gpu = false;
  }

  if (host_is_viz_host) {
    host_frame_sink_manager_ = std::make_unique<viz::HostFrameSinkManager>();
    HostGpuChannelHostFactory::Initialize(established_gpu_channel);
    compositing_mode_reporter_impl_ =
        std::make_unique<viz::CompositingModeReporterImpl>();

    if (base::FeatureList::IsEnabled(features::kVizDisplayCompositor)) {
      auto transport_factory = std::make_unique<VizProcessTransportFactory>(
          HostGpuChannelHostFactory::instance(), GetResizeTaskRunner(),
          compositing_mode_reporter_impl_.get());
      transport_factory->ConnectHostFrameSinkManager();
      ImageTransportFactory::SetFactory(std::move(transport_factory));
    } else {
      frame_sink_manager_impl_ = std::make_unique<viz::FrameSinkManagerImpl>(
          switches::GetDeadlineToSynchronizeSurfaces());
      surface_utils::ConnectWithLocalFrameSinkManager(
          host_frame_sink_manager_.get(), frame_sink_manager_impl_.get());

      ImageTransportFactory::SetFactory(
          std::make_unique<GpuProcessTransportFactory>(
              HostGpuChannelHostFactory::instance(),
              compositing_mode_reporter_impl_.get(), GetResizeTaskRunner()));
    }
  }

 #if defined(USE_AURA)
   if (host_is_viz_host) {
     env_->set_context_factory(GetContextFactory());
     env_->set_context_factory_private(GetContextFactoryPrivate());
   }
 #endif  // defined(USE_AURA)
#endif  // !defined(OS_ANDROID)

#if defined(OS_ANDROID)
  base::trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      tracing::GraphicsMemoryDumpProvider::GetInstance(), "AndroidGraphics",
      nullptr);
#endif

  {
    TRACE_EVENT0("startup", "HostThreadsStarted::Subsystem:AudioMan");
    CreateAudioManager();
  }

  {
    TRACE_EVENT0("startup", "HostThreadsStarted::Subsystem:MidiService");
    midi_service_.reset(new midi::MidiService);
  }

#if defined(OS_WIN)
  //if (base::FeatureList::IsEnabled(features::kHighDynamicRange))
  //  HDRProxy::Initialize();
  system_message_window_.reset(new media::SystemMessageWindowWin);
#elif defined(OS_LINUX) && defined(USE_UDEV)
  device_monitor_linux_.reset(
      new media::DeviceMonitorLinux(io_thread_->task_runner()));
#elif defined(OS_MACOSX)
  device_monitor_mac_.reset(
      new media::DeviceMonitorMac(audio_manager_->GetTaskRunner()));
#endif

#if BUILDFLAG(ENABLE_WEBRTC)
  // Instantiated once using CreateSingletonInstance(), and accessed only using
  // GetInstance(), which is not allowed to create the object. This allows us
  // to ensure that it cannot be used before objects it relies on have been
  // created; namely, WebRtcEventLogManager.
  // Allowed to leak when the host exits.
  WebRTCInternals::CreateSingletonInstance();
#endif

  // RDH needs the IO thread to be created
//  {
   // TRACE_EVENT0("startup",
   //   "HostMainLoop::HostThreadsStarted:InitResourceDispatcherHost");
    // TODO(ananta)
    // We register an interceptor on the ResourceDispatcherHostImpl instance to
    // intercept requests to create handlers for download requests. We need to
    // find a better way to achieve this. Ideally we don't want knowledge of
    // downloads in ResourceDispatcherHostImpl.
    // We pass the task runners for the UI and IO threads as a stopgap approach
    // for now. Eventually variants of these runners would be available in the
    // network service.
    // resource_dispatcher_host_.reset(new ResourceDispatcherHostImpl(
    //     base::Bind(&DownloadResourceHandler::Create),
    //     HostThread::GetTaskRunnerForThread(HostThread::IO),
    //     !parsed_command_line_.HasSwitch(switches::kDisableResourceScheduler)));
    // GetContentClient()->host()->ResourceDispatcherHostCreated();

    // loader_delegate_.reset(new LoaderDelegateImpl());
    // resource_dispatcher_host_->SetLoaderDelegate(loader_delegate_.get());
  //}

  // MediaStreamManager needs the IO thread to be created.
   {
     TRACE_EVENT0("startup",
       "HostMainLoop::HostThreadsStarted:InitMediaStreamManager");
     media_stream_manager_.reset(new MediaStreamManager(
         audio_system_.get(), audio_manager_->GetTaskRunner()));
   }

  // {
  //   TRACE_EVENT0("startup",
  //     "HostMainLoop::HostThreadsStarted:InitSpeechRecognition");
  //   speech_recognition_manager_.reset(new SpeechRecognitionManagerImpl(
  //       audio_system_.get(), audio_manager_.get(),
  //       media_stream_manager_.get()));
  // }

  {
    TRACE_EVENT0(
        "startup",
        "HostMainLoop::HostThreadsStarted::InitUserInputMonitor");
    user_input_monitor_ = media::UserInputMonitor::Create(
        io_thread_->task_runner(), base::ThreadTaskRunnerHandle::Get());
  }

  // Alert the clipboard class to which threads are allowed to access the
  // clipboard:
  std::vector<base::PlatformThreadId> allowed_clipboard_threads;
  // The current thread is the UI thread.
  allowed_clipboard_threads.push_back(base::PlatformThread::CurrentId());
#if defined(OS_WIN)
  // On Windows, clipboard is also used on the IO thread.
  allowed_clipboard_threads.push_back(io_thread_->GetThreadId());
#endif
  ui::Clipboard::SetAllowedThreads(allowed_clipboard_threads);

  if (GpuDataManagerImpl::GetInstance()->GpuProcessStartAllowed() &&
      !established_gpu_channel && always_uses_gpu && host_is_viz_host) {
    TRACE_EVENT_INSTANT0("gpu", "Post task to launch GPU process",
                         TRACE_EVENT_SCOPE_THREAD);
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(base::IgnoreResult(&GpuProcessHost::Get),
                       GpuProcessHost::GPU_PROCESS_KIND_SANDBOXED,
                       true /* force_create */));
  }

#if defined(OS_WIN)
  GpuDataManagerImpl::GetInstance()->RequestGpuSupportedRuntimeVersion();
#endif

#if defined(OS_MACOSX)
  ThemeHelperMac::GetInstance();
  SystemHotkeyHelperMac::GetInstance()->DeferredLoadSystemHotkeys();
#endif  // defined(OS_MACOSX)

#if defined(OS_ANDROID)
  media::SetMediaDrmBridgeClient(GetContentClient()->GetMediaDrmBridgeClient());
#endif

  return result_code_;
}

void HostMainLoop::InitializeMemoryManagementComponent() {
  // TODO(chrisha): Abstract away this construction mess to a helper function,
  // once MemoryPressureMonitor is made a concrete class.
#if defined(OS_CHROMEOS)
  if (chromeos::switches::MemoryPressureHandlingEnabled()) {
    memory_pressure_monitor_ =
        std::make_unique<base::chromeos::MemoryPressureMonitor>(
            chromeos::switches::GetMemoryPressureThresholds());
  }
#elif defined(OS_MACOSX)
  memory_pressure_monitor_ =
      std::make_unique<base::mac::MemoryPressureMonitor>();
#elif defined(OS_WIN)
  //memory_pressure_monitor_ =
  //    CreateWinMemoryPressureMonitor(parsed_command_line_);
#endif

//  if (base::FeatureList::IsEnabled(features::kMemoryCoordinator))
 //   MemoryCoordinatorImpl::GetInstance()->Start();

//   std::unique_ptr<SwapMetricsDriver::Delegate> delegate(
//       base::WrapUnique<SwapMetricsDriver::Delegate>(
//           new SwapMetricsDelegateUma()));

// #if !defined(OS_FUCHSIA)
//   swap_metrics_driver_ =
//       SwapMetricsDriver::Create(std::move(delegate), kSwapMetricsInterval);
//   if (swap_metrics_driver_)
//     swap_metrics_driver_->Start();
// #endif  // !defined(OS_FUCHSIA)
}

bool HostMainLoop::InitializeToolkit() {
  TRACE_EVENT0("startup", "HostMainLoop::InitializeToolkit");

  // TODO(evan): this function is rather subtle, due to the variety
  // of intersecting ifdefs we have.  To keep it easy to follow, there
  // are no #else branches on any #ifs.
  // TODO(stevenjb): Move platform specific code into platform specific Parts
  // (Need to add InitializeToolkit stage to HostParts).
  // See also GTK setup in EarlyInitialization, above, and associated comments.

#if defined(OS_WIN)
  INITCOMMONCONTROLSEX config;
  config.dwSize = sizeof(config);
  config.dwICC = ICC_WIN95_CLASSES;
  if (!InitCommonControlsEx(&config))
    PLOG(FATAL);
#endif

#if defined(USE_AURA)

#if defined(USE_X11)
  if (!parsed_command_line_.HasSwitch(switches::kHeadless) && !gfx::GetXDisplay()) {
    LOG(ERROR) << "Unable to open X display.";
    return false;
  }
#endif
  // Env creates the compositor. Aura widgets need the compositor to be created
  // before they can be initialized by the host.
   env_ = aura::Env::CreateInstance(
       features::IsMusEnabled() ? aura::Env::Mode::MUS : aura::Env::Mode::LOCAL);
#endif  // defined(USE_AURA)

// #if BUILDFLAG(ENABLE_MUS)
//   if (features::IsMusEnabled())
//     image_cursors_set_ = std::make_unique<ui::ImageCursorsSet>();
// #endif

  // if (parts_)
  //   parts_->ToolkitInitialized();

  if (!views::ViewsDelegate::GetInstance())
    views_delegate_ = std::make_unique<DockViewsDelegate>();

  SetConstrainedWindowViewsClient(CreateDockConstrainedWindowViewsClient());

#if defined(USE_AURA)
  if (ShouldCreateWMState())
    wm_state_.reset(new wm::WMState);
#endif

#if defined(OS_LINUX)
  views::LinuxUI::instance()->Initialize();
#endif

  return true;
}

void HostMainLoop::PreMainMessageLoopStart() {
  // if (parts_) {
  //   TRACE_EVENT0("startup",
  //       "HostMainLoop::MainMessageLoopStart:PreMainMessageLoopStart");
  //   parts_->PreMainMessageLoopStart();
  // }
}

void HostMainLoop::PostMainMessageLoopStart() {
  // {
  //   TRACE_EVENT0("startup",
  //                "HostMainLoop::Subsystem:CreateHostThread::IO");
  //   InitializeIOThread();
  // }
  {
    TRACE_EVENT0("startup", "HostMainLoop::Subsystem:SystemMonitor");
    system_monitor_.reset(new base::SystemMonitor);
  }
  {
    TRACE_EVENT0("startup", "HostMainLoop::Subsystem:PowerMonitor");
    std::unique_ptr<base::PowerMonitorSource> power_monitor_source(
        new base::PowerMonitorDeviceSource());
    power_monitor_.reset(
        new base::PowerMonitor(std::move(power_monitor_source)));
  }
  {
    TRACE_EVENT0("startup", "HostMainLoop::Subsystem:HighResTimerManager");
    hi_res_timer_manager_.reset(new base::HighResolutionTimerManager);
  }
  {
    TRACE_EVENT0("startup", "HostMainLoop::Subsystem:NetworkChangeNotifier");
    network_change_notifier_.reset(net::NetworkChangeNotifier::Create());
  }
  {
    TRACE_EVENT0("startup", "HostMainLoop::Subsystem:MediaFeatures");
    media::InitializeMediaLibrary();
  }
  // {
  //   TRACE_EVENT0("startup",
  //                "HostMainLoop::Subsystem:ContentWebUIController");
  //   WebUIControllerFactory::RegisterFactory(
  //       ContentWebUIControllerFactory::GetInstance());
  // }

  {
    TRACE_EVENT0("startup", "HostMainLoop::Subsystem:OnlineStateObserver");
    online_state_observer_.reset(new HostOnlineStateObserver);
  }

  {
    system_stats_monitor_.reset(
        new base::trace_event::TraceEventSystemStatsMonitor(
            base::ThreadTaskRunnerHandle::Get()));
  }

  {
    base::SetRecordActionTaskRunner(
        HostThread::GetTaskRunnerForThread(HostThread::UI));
  }

  if (!base::FeatureList::IsEnabled(::features::kMash)) {
    discardable_shared_memory_manager_ =
        std::make_unique<discardable_memory::DiscardableSharedMemoryManager>();
    // TODO(boliu): kSingleProcess check is a temporary workaround for
    // in-process Android WebView. crbug.com/503724 tracks proper fix.
    if (!parsed_command_line_.HasSwitch(switches::kSingleProcess)) {
      base::DiscardableMemoryAllocator::SetInstance(
          discardable_shared_memory_manager_.get());
    }
  }

  // if (parts_)
  //   parts_->PostMainMessageLoopStart();

#if defined(OS_ANDROID)
  {
    TRACE_EVENT0("startup",
                 "HostMainLoop::Subsystem:HostMediaPlayerManager");
    if (UsingInProcessGpu()) {
      gpu::ScopedSurfaceRequestConduit::SetInstance(
          ScopedSurfaceRequestManager::GetInstance());
    }
  }

  if (!parsed_command_line_.HasSwitch(
      switches::kDisableScreenOrientationLock)) {
    TRACE_EVENT0("startup",
                 "HostMainLoop::Subsystem:ScreenOrientationProvider");
    screen_orientation_delegate_.reset(
        new ScreenOrientationDelegateAndroid());
  }
#endif

  // if (parsed_command_line_.HasSwitch(
  //         switches::kEnableAggressiveDOMStorageFlushing)) {
  //   TRACE_EVENT0("startup",
  //                "HostMainLoop::Subsystem:EnableAggressiveCommitDelay");
  //   DOMStorageArea::EnableAggressiveCommitDelay();
  //   LevelDBWrapperImpl::EnableAggressiveCommitDelay();
  // }

  // Enable memory-infra dump providers.
  InitSkiaEventTracer();

  base::trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      viz::ServerSharedBitmapManager::current(),
      "viz::ServerSharedBitmapManager", nullptr);
  
  base::trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      skia::SkiaMemoryDumpProvider::GetInstance(), "Skia", nullptr);
  
  base::trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      sql::SqlMemoryDumpProvider::GetInstance(), "Sql", nullptr);
}

int HostMainLoop::PreMainMessageLoopRun() {
 //bool normal_init = false;
#if defined(USE_X11)
 ui::TouchFactory::SetTouchDeviceListFromCommandLine();
#endif
 
 std::string message;
 notify_result_ = process_singleton_->NotifyOtherProcessOrCreate();//process_singleton_->NotifyOtherProcessOrCreate(&message);
 switch (notify_result_) {
 case ProcessSingleton::PROCESS_NONE: {
  //(INFO) << "ProcessSingleton::PROCESS_NONE";
  //if(!host_->is_normal_startup())
  //  should_run_ = false;
  
  // No process already running, fall through to starting a new one.
  //normal_init = true;
  break;
 }
 case ProcessSingleton::PROCESS_NOTIFIED: {
   //DLOG(INFO) << "ProcessSingleton::PROCESS_NOTIFIED";
  //std::unique_ptr<base::Environment> env(base::Environment::Create());
  //std::string old_var;
  //if (!env->GetVar("IPC_CHANNEL_ID", &old_var) && !message.empty()) {
  //  env->SetVar("IPC_CHANNEL_ID", message);
  //  LOG(INFO) << "setando var IPC_CHANNEL_ID: " << message;
  //  LOG(INFO) << "var set ?" << (env->GetVar("IPC_CHANNEL_ID", &old_var) ? "true" : "false");
  //}
  //if(!message.empty()) {
  //DLOG(INFO) << "Hello second instance. goodbye! message: " << message;
  host_->controller()->ProcessHostClient(message);
     //<< "our process: " << base::Process::<< " parent process: " << ;
    // const base::CommandLine::StringVector& args = parsed_command_line_.GetArgs();
    // std::string first_query = args.size() > 0 ? args[0] : "";
    // bool repl = first_query.empty();
    // host_->controller()->LaunchCommandClient(message, first_query, repl);
  //} else {
  should_run_ = false;
  //normal_init = false;
  //}
  // TODO: ao inves de apenas booleans, precisamos criar um
  // ** HostStartupDelegate ** e definir as flags necessarias la!
  //    printf("%s\n", base::SysWideToNativeMB(base::UTF16ToWide(
  //        l10n_util::GetStringUTF16(IDS_USED_EXISTING_BROWSER))).c_str());
  // Having a differentiated return type for testing allows for tests to
  // verify proper handling of some switches. When not testing, stick to
  // the standard Unix convention of returning zero when things went as
  // expected.
  //if (parsed_command_line().HasSwitch(switches::kTestType))
  //  return RESULT_CODE_NORMAL_EXIT_PROCESS_NOTIFIED;
  return common::RESULT_CODE_NORMAL_EXIT;
 }

 case ProcessSingleton::PROFILE_IN_USE:
  return common::RESULT_CODE_PROFILE_IN_USE;

 case ProcessSingleton::LOCK_ERROR:
  LOG(ERROR) << "Failed to create a ProcessSingleton for your profile "
   "directory. This means that running multiple instances "
   "would start multiple host processes rather than "
   "opening a new window in the existing process. Aborting "
   "now to avoid profile corruption.";
  return common::RESULT_CODE_PROFILE_IN_USE;

 default:
  NOTREACHED();
 }

 //process_singleton_->Unlock();
 if (notify_result_ == ProcessSingleton::PROCESS_NONE)
  process_singleton_->Cleanup();

 should_run_ = host_->PreMainMessageLoopRun();
 
 // If the MAIN thread blocks, the whole host is unresponsive.
 // Do not allow disk IO from the MAIN thread.
 base::ThreadRestrictions::SetIOAllowed(false);
 if (should_run_) {
// #if defined(OS_POSIX) && !defined(OS_IOS)
//   SetHostSignalHandlers();
// #endif // defined(OS_POSIX) && !defined(OS_IOS)  
  //DLOG(INFO) << "FIXIT: enabling wait on the main thread. We should delegate the Sync()/Wait() to other thread so we dont block the main";
  //base::ThreadRestrictions::DisallowWaiting();
 }

 return result_code_;
}

void HostMainLoop::PreShutdown() {
  //parts_->PreShutdown();
  ui::Clipboard::OnPreShutdownForCurrentThread();
}

base::FilePath HostMainLoop::GetStartupTraceFileName() const {
  base::FilePath trace_file;

#if defined(OS_ANDROID)
  TracingControllerAndroid::GenerateTracingFilePath(&trace_file);
#else
  trace_file = tracing::TraceStartupConfig::GetInstance()->GetResultFile();
  if (trace_file.empty()) {
    // Default to saving the startup trace into the current dir.
    trace_file = base::FilePath().AppendASCII("chrometrace.log");
  }
#endif

  return trace_file;
}

void HostMainLoop::InitStartupTracingForDuration() {
  DCHECK(tracing::TraceStartupConfig::GetInstance()
             ->IsTracingStartupForDuration());

  startup_trace_file_ = GetStartupTraceFileName();

  startup_trace_timer_.Start(
      FROM_HERE,
      base::TimeDelta::FromSeconds(
          tracing::TraceStartupConfig::GetInstance()->GetStartupDuration()),
      this, &HostMainLoop::EndStartupTracing);
}

void HostMainLoop::EndStartupTracing() {
  // Do nothing if startup tracing is already stopped.
  if (!tracing::TraceStartupConfig::GetInstance()->IsEnabled())
    return;

  TracingController::GetInstance()->StopTracing(
      TracingController::CreateFileEndpoint(
          startup_trace_file_,
          base::Bind(OnStoppedStartupTracing, startup_trace_file_)));
}

#if defined(OS_POSIX)
 // static
void HostMainLoop::ProcessSignal(int signal) {
  //DLOG(INFO) << "called HostMainLoop::ProcessSignal..";
  switch (signal) {
    case SIGINT: {
     Host::Instance()->OnShutdown(false);
     break;
    }
    case SIGTERM: {
     Host::Instance()->OnShutdown(true);
     break;
    }
    default:
     NOTREACHED() << "signal " << signal << " not caught";
  }
}
#endif

void HostMainLoop::PerformShutdown() {
  //main_loop_.Quit();
  base::RunLoop::QuitCurrentDeprecated();
}

scoped_refptr<base::SingleThreadTaskRunner> HostMainLoop::GetResizeTaskRunner() {
  #if defined(OS_MACOSX)
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      ui::WindowResizeHelperMac::Get()->task_runner();
  // In tests, WindowResizeHelperMac task runner might not be initialized.
  return task_runner ? task_runner : base::ThreadTaskRunnerHandle::Get();
#else
  return base::ThreadTaskRunnerHandle::Get();
#endif
}

}
