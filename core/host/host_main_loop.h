// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MAIN_LOOP_H__
#define MUMBA_HOST_MAIN_LOOP_H__

#include <memory>

#include "base/macros.h"
#include "base/run_loop.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/timer/timer.h"
#include "base/deferred_sequenced_task_runner.h"
#include "core/common/main_params.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/host/process_singleton.h"
#include "core/host/host_delegate.h"
#include "media/media_buildflags.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "services/viz/public/interfaces/compositing/compositing_mode_watcher.mojom.h"
#include "ui/base/ui_features.h"
#include "ui/views/layout/layout_provider.h"

namespace base {
class CommandLine;
class MessageLoop;
class PowerMonitor;
class HighResolutionTimerManager;
class SystemMonitor;
}  // namespace base

namespace discardable_memory {
class DiscardableSharedMemoryManager;
}

namespace gpu {
class GpuChannelEstablishFactory;
}

namespace net {
class NetworkChangeNotifier;
}  // namespace net

namespace media {
class AudioManager;
class AudioSystem;
#if defined(OS_WIN)
class SystemMessageWindowWin;
#elif defined(OS_LINUX) && defined(USE_UDEV)
class DeviceMonitorLinux;
#endif
class UserInputMonitor;
#if defined(OS_MACOSX)
class DeviceMonitorMac;
#endif
}  // namespace media

namespace midi {
class MidiService;
}  // namespace midi

namespace mojo {
namespace edk {
class ScopedIPCSupport;
}  // namespace edk
}  // namespace mojo

namespace viz {
class CompositingModeReporterImpl;
class FrameSinkManagerImpl;
class HostFrameSinkManager;
}

#if defined(USE_AURA)
namespace aura {
class Env;
}
namespace views {
class MusClient;
}
namespace wm {
class WMState;
}
#endif

namespace ui {
class InputDeviceClient;
}

namespace views {
class ViewsDelegate;
}

namespace host {
class Host;
class HostThread;
class HostSubThread;
class StartupTaskRunner;
class ServiceManagerContext;
class HostOnlineStateObserver;
class TracingControllerImpl;
class MediaStreamManager;
#if defined(OS_ANDROID)
class ScreenOrientationDelegate;
#endif

#if defined(USE_X11)
namespace internal {
class GpuDataManagerVisualProxy;
}
class X11DesktopHandlerObserver;
#endif

class HostMainLoop : public HostDelegate {
public:
  static HostMainLoop* GetInstance();

  HostMainLoop(const common::MainParams& parameters);
  ~HostMainLoop() override;

  int result_code() const { return result_code_; }

  const base::CommandLine& parsed_command_line() const { return parsed_command_line_; }

  media::AudioManager* audio_manager() const { return audio_manager_.get(); }
  base::SequencedTaskRunner* audio_service_runner();
  media::AudioSystem* audio_system() const { return audio_system_.get(); }
  MediaStreamManager* media_stream_manager() const { return media_stream_manager_.get(); }
  
  // TODO: this is supporting renderer host.. should support app now
  // Maybe the right portal for this is on the shell now
  
  //MediaStreamManager* media_stream_manager() const {
  //  return media_stream_manager_.get();
  //}
  media::UserInputMonitor* user_input_monitor() const {
    return user_input_monitor_.get();
  }
  discardable_memory::DiscardableSharedMemoryManager*
  discardable_shared_memory_manager() const {
    return discardable_shared_memory_manager_.get();
  }
  midi::MidiService* midi_service() const { return midi_service_.get(); }

  scoped_refptr<base::SingleThreadTaskRunner> GetResizeTaskRunner();

  gpu::GpuChannelEstablishFactory* gpu_channel_establish_factory() const;

  base::FilePath GetStartupTraceFileName() const;

  const base::FilePath& startup_trace_file() const {
    return startup_trace_file_;
  }

#if defined(OS_ANDROID)
  void SynchronouslyFlushStartupTasks();
#endif  // OS_ANDROID
#if !defined(OS_ANDROID)
  // TODO(fsamuel): We should find an object to own HostFrameSinkManager on all
  // platforms including Android. See http://crbug.com/732507.
  viz::HostFrameSinkManager* host_frame_sink_manager() const {
    return host_frame_sink_manager_.get();
  }

  // TODO(crbug.com/657959): This will be removed once there are no users, as
  // SurfaceManager is being moved out of process.
  viz::FrameSinkManagerImpl* GetFrameSinkManager() const;
#endif
// Fulfills a mojo pointer to the singleton CompositingModeReporter.
  void GetCompositingModeReporter(
      viz::mojom::CompositingModeReporterRequest request);

#if defined(OS_MACOSX) && !defined(OS_IOS)
  media::DeviceMonitorMac* device_monitor_mac() const {
    return device_monitor_mac_.get();
  }
#endif

  void Init();
  void EarlyInitialization();
  bool InitializeToolkit();
  void PreMainMessageLoopStart();
  void MainMessageLoopStart();
  void PostMainMessageLoopStart();
  void CreateStartupTasks();
  void RunMainMessageLoop();
  void QuitMainMessageLoop();
  void ShutdownThreadsAndCleanUp();
  void PreShutdown();
  
  #if defined(OS_POSIX) && !defined(OS_IOS) 
  static void ProcessSignal(int sig);
  #endif 

private:
  void PerformShutdown() override;

  void InitializeMainThread();
  int PreCreateThreads();
  int CreateThreads();
  int HostThreadsStarted();
  int PreMainMessageLoopRun();

  void InitializeMojo();
  void ServiceManagerConnectionStarted(common::ServiceManagerConnection* connection);
  void CreateAudioManager();
  void InitializeMemoryManagementComponent();
  void InitStartupTracingForDuration();
  void EndStartupTracing();
 
  const common::MainParams& parameters_;
  const base::CommandLine& parsed_command_line_;

  //base::RunLoop main_loop_;

  int result_code_;

  bool created_threads_;

  std::unique_ptr<base::MessageLoop> main_message_loop_;

  std::unique_ptr<StartupTaskRunner> startup_task_runner_;

  std::unique_ptr<ProcessSingleton> process_singleton_;

  std::unique_ptr<Host> host_;

  std::unique_ptr<HostThread> main_thread_;

  std::unique_ptr<HostSubThread> io_thread_;
  std::unique_ptr<HostSubThread> file_thread_;
  std::unique_ptr<HostSubThread> db_thread_;
  std::unique_ptr<HostSubThread> rpc_thread_;
  std::unique_ptr<HostSubThread> dispatcher_thread_;
  std::unique_ptr<HostSubThread> notification_thread_;
  std::unique_ptr<HostSubThread> process_launcher_thread_;
  std::unique_ptr<HostSubThread> watchdog_thread_;
#if defined(USE_X11)
  std::unique_ptr<internal::GpuDataManagerVisualProxy>
      gpu_data_manager_visual_proxy_;
#endif
#if defined(USE_AURA)
  std::unique_ptr<aura::Env> env_;
#endif

   // Members initialized in |InitStartupTracingForDuration()| ------------------
  base::FilePath startup_trace_file_;

  // This timer initiates trace file saving.
  base::OneShotTimer startup_trace_timer_;

  // Members initialized in |HostThreadsStarted()| --------------------------
  std::unique_ptr<ServiceManagerContext> service_manager_context_;
  std::unique_ptr<mojo::edk::ScopedIPCSupport> mojo_ipc_support_;

  // |user_input_monitor_| has to outlive |audio_manager_|, so declared first.
  std::unique_ptr<media::UserInputMonitor> user_input_monitor_;
  std::unique_ptr<media::AudioManager> audio_manager_;
  scoped_refptr<base::DeferredSequencedTaskRunner> audio_service_runner_;
  std::unique_ptr<media::AudioSystem> audio_system_;

  std::unique_ptr<midi::MidiService> midi_service_;
  std::unique_ptr<MediaStreamManager> media_stream_manager_;
  std::unique_ptr<discardable_memory::DiscardableSharedMemoryManager>
      discardable_shared_memory_manager_;
  std::unique_ptr<TracingControllerImpl> tracing_controller_;    
#if !defined(OS_ANDROID)
  std::unique_ptr<viz::HostFrameSinkManager> host_frame_sink_manager_;
  // This is owned here so that SurfaceManager will be accessible in process
  // when display is in the same process. Other than using SurfaceManager,
  // access to |in_process_frame_sink_manager_| should happen via
  // |host_frame_sink_manager_| instead which uses Mojo. See
  // http://crbug.com/657959.
  std::unique_ptr<viz::FrameSinkManagerImpl> frame_sink_manager_impl_;

  // Reports on the compositing mode in the system for clients to submit
  // resources of the right type. This is null if the display compositor
  // is not in this process.
  std::unique_ptr<viz::CompositingModeReporterImpl>
      compositing_mode_reporter_impl_;
#endif
  std::unique_ptr<base::SystemMonitor> system_monitor_;
  std::unique_ptr<base::PowerMonitor> power_monitor_;
  std::unique_ptr<base::HighResolutionTimerManager> hi_res_timer_manager_;
  std::unique_ptr<net::NetworkChangeNotifier> network_change_notifier_;

  // Per-process listener for online state changes.
  std::unique_ptr<HostOnlineStateObserver> online_state_observer_;
  std::unique_ptr<base::trace_event::TraceEventSystemStatsMonitor>
      system_stats_monitor_;

#if defined(OS_WIN)
  std::unique_ptr<media::SystemMessageWindowWin> system_message_window_;
#elif defined(OS_LINUX) && defined(USE_UDEV)
  std::unique_ptr<media::DeviceMonitorLinux> device_monitor_linux_;
#elif defined(OS_MACOSX) && !defined(OS_IOS)
  std::unique_ptr<media::DeviceMonitorMac> device_monitor_mac_;
#endif

  base::FilePath root_dir_;

  ProcessSingleton::NotifyResult notify_result_;

  bool should_run_;

  bool is_first_run_;

  base::Closure loop_quit_;

  std::unique_ptr<views::ViewsDelegate> views_delegate_;
  std::unique_ptr<views::LayoutProvider> layout_provider_;

#if defined(USE_AURA)
  // Not created when running in ash::Config::MUS.
  std::unique_ptr<wm::WMState> wm_state_;

  // Only used when running in ash::Config::MASH.
  std::unique_ptr<views::MusClient> mus_client_;

  // Subscribes to updates about input-devices.
  std::unique_ptr<ui::InputDeviceClient> input_device_client_;
#endif

#if defined(USE_X11)
  std::unique_ptr<X11DesktopHandlerObserver> x_desktop_handler_observer_;
#endif 

  base::WeakPtrFactory<HostMainLoop> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(HostMainLoop);
};

}

#endif
