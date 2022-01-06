// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/application_thread.h"

#include <signal.h>
#include <string>
#include <utility>

#include "base/allocator/allocator_extension.h"
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/memory/singleton.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/path_service.h"
#include "base/process/process_metrics.h"
#include "base/run_loop.h"
#include "base/values.h"
#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/debug/alias.h"
#include "base/debug/leak_annotations.h"
#include "base/debug/profiler.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop_current.h"
#include "base/message_loop/timer_slack.h"
#include "base/memory/discardable_memory_allocator.h"
#include "base/memory/memory_coordinator_client_registry.h"
#include "base/memory/shared_memory.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string16.h"
#include "base/strings/string_split.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_restrictions.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "components/tracing/child/child_trace_message_filter.h"
#include "components/discardable_memory/client/client_discardable_shared_memory_manager.h"
#include "components/metrics/public/interfaces/single_sample_metrics.mojom.h"
#include "components/metrics/single_sample_metrics.h"
#include "components/viz/client/client_layer_tree_frame_sink.h"
#include "components/viz/client/hit_test_data_provider.h"
#include "components/viz/client/hit_test_data_provider_draw_quad.h"
#include "components/viz/client/hit_test_data_provider_surface_layer.h"
#include "components/viz/client/local_surface_id_provider.h"
#include "components/viz/common/features.h"
#include "components/viz/common/frame_sinks/copy_output_request.h"
#include "core/shared/common/child_histogram_fetcher_impl.h"
#include "core/shared/common/gpu_stream_constants.h"
#include "core/shared/common/service_worker/worker_native_client_factory.h"
#include "core/shared/application/blink_platform_impl.h"
#include "core/shared/application/resource_dispatcher.h"
#include "core/shared/application/application_process.h"
#include "core/shared/application/thread_safe_sender.h"
#include "core/shared/application/frame_swap_message_queue.h"
#include "core/shared/application/queue_message_swap_promise.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/application/categorized_worker_pool.h"
#include "core/shared/application/media/gpu/gpu_video_accelerator_factories_impl.h"
#include "core/shared/application/media/audio/audio_renderer_mixer_manager.h"
#include "core/shared/application/media/webrtc/peer_connection_tracker.h"
#include "core/shared/application/media/webrtc/peer_connection_dependency_factory.h"
#include "core/shared/application/media/stream/aec_dump_message_filter.h"
#include "core/shared/application/media/video_capture_impl_manager.h"
#include "core/shared/application/p2p/socket_dispatcher.h"
#include "core/shared/application/service_worker/embedded_worker_instance_client_impl.h"
#include "core/shared/application/service_worker/service_worker_context_client.h"
#include "core/shared/application/service_worker/service_worker_message_filter.h"
#include "core/shared/application/notifications/notification_dispatcher.h"
#include "core/shared/application/appcache/appcache_dispatcher.h"
#include "core/shared/application/appcache/appcache_frontend_impl.h"
#include "core/shared/application/fileapi/file_system_dispatcher.h"
#include "core/shared/application/automation/automation_context.h"
#include "core/shared/application/automation/animation_dispatcher.h"
#include "core/shared/application/automation/page_dispatcher.h"
#include "core/shared/common/compositor_helper.h"
//#include "core/shared/application/mus/application_widget_window_tree_client_factory.h"
//#include "core/shared/application/mus/application_window_tree_client.h"
//#include "core/shared/common/field_trial_recorder.mojom.h"
#include "core/shared/common/connection_filter.h"
#include "core/shared/common/client.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/mojo_channel_switches.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/common/simple_connection_filter.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "core/shared/common/application_window_surface_properties.h"
#include "core/shared/common/frame_messages.h"
#include "cc/base/histograms.h"
#include "cc/base/switches.h"
#include "cc/blink/web_layer_impl.h"
#include "cc/raster/task_graph_runner.h"
#include "cc/trees/layer_tree_frame_sink.h"
#include "cc/trees/layer_tree_host_common.h"
#include "cc/trees/layer_tree_settings.h"
#include "ipc/ipc_channel_mojo.h"
#include "ipc/ipc_logging.h"
#include "ipc/ipc_platform_file.h"
#include "ipc/ipc_sync_channel.h"
#include "ipc/ipc_sync_message_filter.h"
#include "rpc/grpc.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/incoming_broker_client_invitation.h"
#include "mojo/edk/embedder/named_platform_channel_pair.h"
#include "mojo/edk/embedder/platform_channel_pair.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "mojo/edk/embedder/named_platform_handle_utils.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "mojo/public/cpp/system/buffer.h"
#include "mojo/public/cpp/system/platform_handle.h"
#include "services/device/public/cpp/power_monitor/power_monitor_broadcast_source.h"
#include "services/resource_coordinator/public/cpp/memory_instrumentation/client_process_impl.h"
#include "services/resource_coordinator/public/mojom/memory_instrumentation/memory_instrumentation.mojom.h"
#include "services/resource_coordinator/public/mojom/service_constants.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/runner/common/client_util.h"
#include "services/service_manager/sandbox/sandbox_type.h"
#include "services/service_manager/public/cpp/service_context.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/ui/public/cpp/gpu/context_provider_command_buffer.h"
#include "services/ui/public/cpp/gpu/gpu.h"
#include "services/ui/public/interfaces/constants.mojom.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/client/shared_memory_limits.h"
#include "gpu/config/gpu_switches.h"
#include "gpu/ipc/client/command_buffer_proxy_impl.h"
#include "gpu/ipc/client/gpu_channel_host.h"
#include "ipc/ipc_channel_handle.h"
#include "ipc/ipc_channel_mojo.h"
#include "ipc/ipc_platform_file.h"
#include "media/base/media.h"
#include "media/base/media_switches.h"
#include "media/media_buildflags.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "net/base/net_errors.h"
#include "net/base/port_util.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/url_util.h"
#include "skia/ext/event_tracer_impl.h"
#include "skia/ext/skia_memory_dump_provider.h"
#include "gin/v8_initializer.h"
#include "third_party/blink/public/platform/scheduler/child/webthread_base.h"
#include "third_party/blink/public/platform/scheduler/web_main_thread_scheduler.h"
#include "third_party/blink/public/platform/web_cache.h"
#include "third_party/blink/public/platform/web_image_generator.h"
#include "third_party/blink/public/platform/web_memory_coordinator.h"
#include "third_party/blink/public/platform/web_network_state_notifier.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_thread.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_script_controller.h"
#include "third_party/blink/public/web/web_security_policy.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/crypto.h"
#include "third_party/skia/include/core/SkGraphics.h"
#include "ui/base/layout.h"
#include "ui/base/ui_base_features.h"
#include "ui/base/ui_base_switches.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/display/display_switches.h"
#include "ui/gl/gl_switches.h"
#include "url/url_util.h"

#if defined(OS_POSIX)
#include "base/posix/global_descriptors.h"
#include "core/shared/common/content_descriptors.h"
#endif

#if defined(USE_GLIB)
#include <glib.h>
#endif

// from RenderThreadImpl


// #include "core/shared/application/input/widget_input_handler_manager.h"
//#include "core/shared/application/loader/resource_dispatcher.h"
//#include "core/shared/application/media/audio_renderer_mixer_manager.h"
//#include "core/shared/application/media/gpu/gpu_video_accelerator_factories_impl.h"
//#include "core/shared/application/media/midi/midi_message_filter.h"
//#include "core/shared/application/media/render_media_client.h"
//#include "core/shared/application/media/stream/media_stream_center.h"
//#include "core/shared/application/media/video_capture_impl_manager.h"
//#include "core/shared/application/mus/application_widget_window_tree_client_factory.h"
//#include "core/shared/application/mus/renderer_window_tree_client.h"


#if defined(OS_ANDROID)
#include <cpu-features.h>
#include "core/shared/application/android/synchronous_layer_tree_frame_sink.h"
#include "core/shared/application/media/android/stream_texture_factory.h"
#include "media/base/android/media_codec_util.h"
#endif

#if defined(OS_WIN)
#include <windows.h>
#include <objbase.h>
#endif

#if defined(OS_MACOSX)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

// End of RenderThreadImpl includes

namespace application {

//ApplicationThread* g_application_thread = nullptr;

namespace {

// How long to wait for a connection to the browser process before giving up.
const int kConnectionTimeoutS = 15;

const int64_t kInitialIdleHandlerDelayMs = 1000;
const int64_t kLongIdleHandlerDelayMs = 30 * 1000;

const size_t kImageCacheSingleAllocationByteLimit = 64 * 1024 * 1024;

base::LazyInstance<base::ThreadLocalPointer<ApplicationThread>>::DestructorAtExit
    g_lazy_tls = LAZY_INSTANCE_INITIALIZER;

base::LazyInstance<scoped_refptr<base::SingleThreadTaskRunner>>::
    DestructorAtExit g_main_task_runner = LAZY_INSTANCE_INITIALIZER;

// This isn't needed on Windows because there the sandbox's job object
// terminates child processes automatically. For unsandboxed processes (i.e.
// plugins), PluginThread has EnsureTerminateMessageFilter.
#if defined(OS_POSIX)

#if defined(ADDRESS_SANITIZER) || defined(LEAK_SANITIZER) || \
    defined(MEMORY_SANITIZER) || defined(THREAD_SANITIZER) || \
    defined(UNDEFINED_SANITIZER)
// A thread delegate that waits for |duration| and then exits the process with
// _exit(0).
class WaitAndExitDelegate : public base::PlatformThread::Delegate {
 public:
  explicit WaitAndExitDelegate(base::TimeDelta duration)
      : duration_(duration) {}

  void ThreadMain() override {
    base::PlatformThread::Sleep(duration_);
    _exit(0);
  }

 private:
  const base::TimeDelta duration_;
  DISALLOW_COPY_AND_ASSIGN(WaitAndExitDelegate);
};

bool CreateWaitAndExitThread(base::TimeDelta duration) {
  std::unique_ptr<WaitAndExitDelegate> delegate(
      new WaitAndExitDelegate(duration));

  const bool thread_created =
      base::PlatformThread::CreateNonJoinable(0, delegate.get());
  if (!thread_created)
    return false;

  // A non joinable thread has been created. The thread will either terminate
  // the process or will be terminated by the process. Therefore, keep the
  // delegate object alive for the lifetime of the process.
  WaitAndExitDelegate* leaking_delegate = delegate.release();
  ANNOTATE_LEAKING_OBJECT_PTR(leaking_delegate);
  ignore_result(leaking_delegate);
  return true;
}
#endif

class SuicideOnChannelErrorFilter : public IPC::MessageFilter {
 public:
  // IPC::MessageFilter
  void OnChannelError() override {
    // For renderer/worker processes:
    // On POSIX, at least, one can install an unload handler which loops
    // forever and leave behind a renderer process which eats 100% CPU forever.
    //
    // This is because the terminate signals (FrameMsg_BeforeUnload and the
    // error from the IPC sender) are routed to the main message loop but never
    // processed (because that message loop is stuck in V8).
    //
    // One could make the browser SIGKILL the renderers, but that leaves open a
    // large window where a browser failure (or a user, manually terminating
    // the browser because "it's stuck") will leave behind a process eating all
    // the CPU.
    //
    // So, we install a filter on the sender so that we can process this event
    // here and kill the process.
    base::debug::StopProfiling();
#if defined(ADDRESS_SANITIZER) || defined(LEAK_SANITIZER) || \
    defined(MEMORY_SANITIZER) || defined(THREAD_SANITIZER) || \
    defined(UNDEFINED_SANITIZER)
    // Some sanitizer tools rely on exit handlers (e.g. to run leak detection,
    // or dump code coverage data to disk). Instead of exiting the process
    // immediately, we give it 60 seconds to run exit handlers.
    CHECK(CreateWaitAndExitThread(base::TimeDelta::FromSeconds(60)));
#if defined(LEAK_SANITIZER)
    // Invoke LeakSanitizer early to avoid detecting shutdown-only leaks. If
    // leaks are found, the process will exit here.
    __lsan_do_leak_check();
#endif
#else
    _exit(0);
#endif
  }

 protected:
  ~SuicideOnChannelErrorFilter() override {}
};

#endif  // OS(POSIX)

#if defined(OS_ANDROID)
// A class that allows for triggering a clean shutdown from another
// thread through draining the main thread's msg loop.
class QuitClosure {
 public:
  QuitClosure();
  ~QuitClosure();

  void BindToMainThread();
  void PostQuitFromNonMainThread();

 private:
  static void PostClosure(
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
      base::Closure closure);

  base::Lock lock_;
  base::ConditionVariable cond_var_;
  base::Closure closure_;
};

QuitClosure::QuitClosure() : cond_var_(&lock_) {
}

QuitClosure::~QuitClosure() {
}

void QuitClosure::PostClosure(
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
    base::Closure closure) {
  task_runner->PostTask(FROM_HERE, closure);
}

void QuitClosure::BindToMainThread() {
  base::AutoLock lock(lock_);
  scoped_refptr<base::SingleThreadTaskRunner> task_runner(
      base::ThreadTaskRunnerHandle::Get());
  base::Closure quit_closure =
      base::MessageLoopCurrent::Get()->QuitWhenIdleClosure();
  closure_ = base::Bind(&QuitClosure::PostClosure, task_runner, quit_closure);
  cond_var_.Signal();
}

void QuitClosure::PostQuitFromNonMainThread() {
  base::AutoLock lock(lock_);
  while (closure_.is_null())
    cond_var_.Wait();

  closure_.Run();
}

base::LazyInstance<QuitClosure>::DestructorAtExit g_quit_closure =
    LAZY_INSTANCE_INITIALIZER;
#endif

std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation>
InitializeMojoIPCChannel() {
  TRACE_EVENT0("startup", "InitializeMojoIPCChannel");
  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  std::string channel_name = "/tmp/";
  channel_name.append(command_line.GetSwitchValueASCII("uuid"));
  mojo::edk::NamedPlatformHandle named_handle(channel_name);
  mojo::ScopedPlatformHandle platform_channel =
  mojo::edk::CreateClientHandle(named_handle);
  if (!platform_channel.is_valid())
    return nullptr;

  std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation> invitation =
   mojo::edk::IncomingBrokerClientInvitation::Accept(
      mojo::edk::ConnectionParams(mojo::edk::TransportProtocol::kLegacy,
                                  std::move(platform_channel)));
  return invitation;
}

class ChannelBootstrapFilter : public common::ConnectionFilter {
 public:
  explicit ChannelBootstrapFilter(IPC::mojom::ChannelBootstrapPtrInfo bootstrap)
      : bootstrap_(std::move(bootstrap)) {}

 private:
  // ConnectionFilter:
  void OnBindInterface(const service_manager::BindSourceInfo& source_info,
                       const std::string& interface_name,
                       mojo::ScopedMessagePipeHandle* interface_pipe,
                       service_manager::Connector* connector) override {
    //DLOG(INFO) << " caller: '" << source_info.identity.name() << "' service: '" << interface_name << "'";
    if (source_info.identity.name() != common::mojom::kHostServiceName) {
      //DLOG(ERROR) << "calling binder '" << source_info.identity.name() << "' not host. not binding";
      return;
    }

    if (interface_name == IPC::mojom::ChannelBootstrap::Name_) {
      DCHECK(bootstrap_.is_valid());
      mojo::FuseInterface(
          IPC::mojom::ChannelBootstrapRequest(std::move(*interface_pipe)),
          std::move(bootstrap_));
    } else {
      //DLOG(INFO) << " '" << interface_name << "' not binded";
    }
  }

  IPC::mojom::ChannelBootstrapPtrInfo bootstrap_;

  DISALLOW_COPY_AND_ASSIGN(ChannelBootstrapFilter);
};

class ApplicationLocalSurfaceIdProvider : public viz::LocalSurfaceIdProvider {
 public:
  const viz::LocalSurfaceId& GetLocalSurfaceIdForFrame(
      const viz::CompositorFrame& frame) override {
    auto new_surface_properties =
        common::ApplicationWindowSurfaceProperties::FromCompositorFrame(frame);
    if (!parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId()
             .is_valid() ||
        new_surface_properties != surface_properties_) {
      parent_local_surface_id_allocator_.GenerateId();
      surface_properties_ = new_surface_properties;
    }
    return parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId();
  }

 private:
  viz::ParentLocalSurfaceIdAllocator parent_local_surface_id_allocator_;
  common::ApplicationWindowSurfaceProperties surface_properties_;
};

// This factory is used to defer binding of the InterfacePtr to the compositor
// thread.
class UkmRecorderFactoryImpl : public cc::UkmRecorderFactory {
 public:
  explicit UkmRecorderFactoryImpl(
      std::unique_ptr<service_manager::Connector> connector)
      : connector_(std::move(connector)) {
    DCHECK(connector_);
  }
  ~UkmRecorderFactoryImpl() override = default;

  std::unique_ptr<ukm::UkmRecorder> CreateRecorder() override {
    return ukm::MojoUkmRecorder::Create(connector_.get());
  }

 private:
  std::unique_ptr<service_manager::Connector> connector_;
};

std::string GetApplicationNameFromUrl(const std::string& url) {
  std::string result = url;
  result = result.substr(0, result.find_first_of(":"));
  return result;
}

scoped_refptr<ui::ContextProviderCommandBuffer> CreateOffscreenContext(
    scoped_refptr<gpu::GpuChannelHost> gpu_channel_host,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
    const gpu::SharedMemoryLimits& limits,
    bool support_locking,
    bool support_gles2_interface,
    bool support_raster_interface,
    bool support_oop_rasterization,
    bool support_grcontext,
    ui::command_buffer_metrics::ContextType type,
    int32_t stream_id,
    gpu::SchedulingPriority stream_priority) {
  DCHECK(gpu_channel_host);
  // This is used to create a few different offscreen contexts:
  // - The shared main thread context, used by blink for 2D Canvas.
  // - The compositor worker context, used for GPU raster.
  // - The media context, used for accelerated video decoding.
  // This is for an offscreen context, so the default framebuffer doesn't need
  // alpha, depth, stencil, antialiasing.
  gpu::ContextCreationAttribs attributes;
  attributes.alpha_size = -1;
  attributes.depth_size = 0;
  attributes.stencil_size = 0;
  attributes.samples = 0;
  attributes.sample_buffers = 0;
  attributes.bind_generates_resource = false;
  attributes.lose_context_when_out_of_memory = true;
  attributes.enable_gles2_interface = support_gles2_interface;
  attributes.enable_raster_interface = support_raster_interface;
  attributes.enable_oop_rasterization = support_oop_rasterization;

  bool enable_raster_decoder =
      base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kEnableRasterDecoder);
  // --enable-raster-decoder supports raster interface, but not
  // gles2 interface
  attributes.enable_raster_decoder = enable_raster_decoder &&
                                     support_raster_interface &&
                                     !support_gles2_interface;

  const bool automatic_flushes = false;
  return base::MakeRefCounted<ui::ContextProviderCommandBuffer>(
      std::move(gpu_channel_host), gpu_memory_buffer_manager, stream_id,
      stream_priority, gpu::kNullSurfaceHandle,
      GURL("mumba://gpu/ApplicationThread::CreateOffscreenContext/" +
           ui::command_buffer_metrics::ContextTypeToString(type)),
      automatic_flushes, support_locking, support_grcontext, limits, attributes,
      type);
}

//const char kV8NativesDataDescriptor[] = "v8_natives_data";
const char kV8SnapshotDataDescriptor[] = "v8_snapshot_data";
//const char kV8Snapshot32DataDescriptor[] = "v8_snapshot_32_data";
//const char kV8Snapshot64DataDescriptor[] = "v8_snapshot_64_data";
//const char kV8ContextSnapshotDataDescriptor[] = "v8_context_snapshot_data";

// #if defined(V8_USE_EXTERNAL_STARTUP_DATA)// && defined(OS_ANDROID)
// #if defined __LP64__
// #define kV8SnapshotDataDescriptor kV8Snapshot64DataDescriptor
// #else
// #define kV8SnapshotDataDescriptor kV8Snapshot32DataDescriptor
// #endif
// #endif

//#if defined(V8_USE_EXTERNAL_STARTUP_DATA)
void LoadV8SnapshotFile() {
#if defined(USE_V8_CONTEXT_SNAPSHOT)
  static constexpr gin::V8Initializer::V8SnapshotFileType kSnapshotType =
      gin::V8Initializer::V8SnapshotFileType::kWithAdditionalContext;
  static const char* snapshot_data_descriptor =
      kV8ContextSnapshotDataDescriptor;
#else
  static constexpr gin::V8Initializer::V8SnapshotFileType kSnapshotType =
      gin::V8Initializer::V8SnapshotFileType::kDefault;
  static const char* snapshot_data_descriptor = kV8SnapshotDataDescriptor;
#endif  // USE_V8_CONTEXT_SNAPSHOT
  ALLOW_UNUSED_LOCAL(kSnapshotType);
  ALLOW_UNUSED_LOCAL(snapshot_data_descriptor);

// #if defined(OS_POSIX) && !defined(OS_MACOSX)
//   base::FileDescriptorStore& file_descriptor_store =
//       base::FileDescriptorStore::GetInstance();
//   base::MemoryMappedFile::Region region;
//   base::ScopedFD fd =
//       file_descriptor_store.MaybeTakeFD(snapshot_data_descriptor, &region);
//   if (fd.is_valid()) {
//     gin::V8Initializer::LoadV8SnapshotFromFD(fd.get(), region.offset,
//                                              region.size, kSnapshotType);
//     return;
//   }
// #endif  // OS_POSIX && !OS_MACOSX

//#if !defined(CHROME_MULTIPLE_DLL_BROWSER)
  gin::V8Initializer::LoadV8Snapshot(kSnapshotType);
//#endif  // !CHROME_MULTIPLE_DLL_BROWSER
}

void LoadV8NativesFile() {
// #if defined(OS_POSIX) && !defined(OS_MACOSX)
//   base::FileDescriptorStore& file_descriptor_store =
//       base::FileDescriptorStore::GetInstance();
//   base::MemoryMappedFile::Region region;
//   base::ScopedFD fd =
//       file_descriptor_store.MaybeTakeFD(kV8NativesDataDescriptor, &region);
//   if (fd.is_valid()) {
//     gin::V8Initializer::LoadV8NativesFromFD(fd.get(), region.offset,
//                                             region.size);
//     return;
//   }
// #endif  // OS_POSIX && !OS_MACOSX
// #if !defined(CHROME_MULTIPLE_DLL_BROWSER)
  gin::V8Initializer::LoadV8Natives();
//#endif  // !CHROME_MULTIPLE_DLL_BROWSER
}
//#endif  // V8_USE_EXTERNAL_STARTUP_DATA

void InitializeV8IfNeeded() {
//#if defined(V8_USE_EXTERNAL_STARTUP_DATA)
  LoadV8SnapshotFile();
  LoadV8NativesFile();
  //gin::V8Initializer::Initialize(gin::IsolateHolder::kNonStrictMode, gin::IsolateHolder::kStableAndExperimentalV8Extras);
//#endif  // V8_USE_EXTERNAL_STARTUP_DATA
}

}  // namespace

//ApplicationThread* ApplicationThread::Get() {
//  return ApplicationThread::current();
//}

ApplicationThread::Options::Options()
    : auto_start_service_manager_connection(true), connect_to_browser(false) {}

ApplicationThread::Options::Options(const Options& other) = default;

ApplicationThread::Options::~Options() {
}

ApplicationThread::Options::Builder::Builder() {
}

ApplicationThread::Options::Builder&
ApplicationThread::Options::Builder::InBrowserProcess(
    const common::InProcessChildThreadParams& params) {
  options_.host_process_io_runner = params.io_runner();
  options_.in_process_service_request_token = params.service_request_token();
  options_.broker_client_invitation = params.broker_client_invitation();
  return *this;
}

ApplicationThread::Options::Builder&
ApplicationThread::Options::Builder::AutoStartServiceManagerConnection(
    bool auto_start) {
  options_.auto_start_service_manager_connection = auto_start;
  return *this;
}

ApplicationThread::Options::Builder&
ApplicationThread::Options::Builder::ConnectToBrowser(
    bool connect_to_browser_parms) {
  options_.connect_to_browser = connect_to_browser_parms;
  return *this;
}

ApplicationThread::Options::Builder&
ApplicationThread::Options::Builder::AddStartupFilter(
    IPC::MessageFilter* filter) {
  options_.startup_filters.push_back(filter);
  return *this;
}

ApplicationThread::Options::Builder&
ApplicationThread::Options::Builder::IPCTaskRunner(
    scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_parms) {
  options_.ipc_task_runner = ipc_task_runner_parms;
  return *this;
}

ApplicationThread::Options ApplicationThread::Options::Builder::Build() {
  return options_;
}

ApplicationThread::ApplicationThreadMessageRouter::ApplicationThreadMessageRouter(
    IPC::Sender* sender)
    : sender_(sender) {}

bool ApplicationThread::ApplicationThreadMessageRouter::Send(IPC::Message* msg) {
  return sender_->Send(msg);
}

bool ApplicationThread::ApplicationThreadMessageRouter::RouteMessage(
    const IPC::Message& msg) {
  bool handled = IPC::MessageRouter::RouteMessage(msg);
#if defined(OS_ANDROID)
  if (!handled && msg.is_sync()) {
    IPC::Message* reply = IPC::SyncMessage::GenerateReply(&msg);
    reply->set_reply_error();
    Send(reply);
  }
#endif
  return handled;
}

ApplicationThread::ApplicationThread(
  void* instance_state,
  int application_process_id,  
  int application_window_id,
  const std::string& initial_url,
  std::unique_ptr<base::MessageLoop> message_loop,
  std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
  CWindowCallbacks window_callbacks, 
  void* window_state,                  
  CApplicationCallbacks app_callbacks,
  bool headless)
    : routing_id_(application_window_id), //routing_id_(MSG_ROUTING_NONE),
      application_window_id_(application_window_id), 
      instance_state_(instance_state),
      app_callbacks_(std::move(app_callbacks)),
      message_loop_(std::move(message_loop)),
      route_provider_binding_(this),
      router_(this),
      main_thread_runner_(message_loop_->task_runner()),
      channel_connected_factory_(
          new base::WeakPtrFactory<ApplicationThread>(this)),
      window_dispatcher_(std::make_unique<application::ApplicationWindowDispatcher>(this, std::move(window_callbacks), window_state)),
      application_binding_(this),
      application_process_id_(static_cast<int32_t>(application_process_id)),
      main_thread_scheduler_(std::move(scheduler)),
      categorized_worker_pool_(new CategorizedWorkerPool()),
      binder_registry_(nullptr),
      is_scroll_animator_enabled_(false),
      initial_url_(initial_url),
      //media_factory_(this,
      //               base::Bind(&ApplicationThread::RequestOverlayRoutingToken,
      //                          base::Unretained(this))),
      compositing_mode_watcher_binding_(this),
      compositor_helper_(std::make_unique<common::CompositorHelper>(this)),
      frame_swap_message_queue_(new FrameSwapMessageQueue(routing_id_)),
      headless_(headless),
      weak_factory_(this) {
  scoped_refptr<base::SingleThreadTaskRunner> test_task_counter;

  application_name_ = GetApplicationNameFromUrl(initial_url_);

  Init(test_task_counter,
       Options::Builder()
              .ConnectToBrowser(true)
              .IPCTaskRunner(nullptr) 
              .Build());
}

ApplicationThread::ApplicationThread(
    void* instance_state,
    int application_process_id,  
    int application_window_id,
    const std::string& initial_url,
    std::unique_ptr<base::MessageLoop> message_loop,
    std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
    CWindowCallbacks window_callbacks, 
    void* window_state,
    CApplicationCallbacks app_callbacks,
    const Options& options,
    bool headless)
    : routing_id_(application_window_id), // ? why not MSG..NONE
      application_window_id_(application_window_id),
      instance_state_(instance_state),
      app_callbacks_(std::move(app_callbacks)),
      message_loop_(std::move(message_loop)),
      route_provider_binding_(this),
      router_(this),
      main_thread_runner_(message_loop_->task_runner()),
      host_process_io_runner_(options.host_process_io_runner),
      channel_connected_factory_(
          new base::WeakPtrFactory<ApplicationThread>(this)),
      ipc_task_runner_(options.ipc_task_runner),
      window_dispatcher_(std::make_unique<application::ApplicationWindowDispatcher>(this, std::move(window_callbacks), window_state)),
      application_binding_(this),
      application_process_id_(static_cast<int32_t>(application_process_id)),
      main_thread_scheduler_(std::move(scheduler)),
      categorized_worker_pool_(new CategorizedWorkerPool()),
      binder_registry_(nullptr),
      is_scroll_animator_enabled_(false),
      initial_url_(initial_url),
      //media_factory_(this,
      //               base::Bind(&ApplicationThread::RequestOverlayRoutingToken,
      //                          base::Unretained(this))),
      compositing_mode_watcher_binding_(this),
      compositor_helper_(std::make_unique<common::CompositorHelper>(this)),
      headless_(headless),
      weak_factory_(this) {
  scoped_refptr<base::SingleThreadTaskRunner> test_task_counter;
  
  application_name_ = GetApplicationNameFromUrl(initial_url_);
  Init(test_task_counter, options);
}

scoped_refptr<base::SingleThreadTaskRunner> ApplicationThread::GetIOTaskRunner() {
  if (IsInHostProcess())
    return host_process_io_runner_;
  return ApplicationProcess::current()->io_task_runner();
}

scoped_refptr<base::SingleThreadTaskRunner> ApplicationThread::GetIPCTaskRunner() {
  //return ipc_task_runner_;
  return message_loop()->task_runner();//base::ThreadTaskRunnerHandle::Get();
}

void ApplicationThread::ConnectChannel(
    mojo::edk::IncomingBrokerClientInvitation* invitation) {
  DCHECK(service_manager_connection_);
  IPC::mojom::ChannelBootstrapPtr bootstrap;
  mojo::ScopedMessagePipeHandle handle =
      mojo::MakeRequest(&bootstrap).PassMessagePipe();
  service_manager_connection_->AddConnectionFilter(
      std::make_unique<ChannelBootstrapFilter>(bootstrap.PassInterface()));

  channel_->Init(
      IPC::ChannelMojo::CreateClientFactory(
          std::move(handle), ApplicationProcess::current()->io_task_runner(),
          ipc_task_runner_ ? ipc_task_runner_
                           : base::ThreadTaskRunnerHandle::Get()),
      true /* create_pipe_now */);
}

void ApplicationThread::Init(
  const scoped_refptr<base::SingleThreadTaskRunner>& resource_task_queue,
  const Options& options) {
  TRACE_EVENT0("startup", "ApplicationThread::Init");
  g_lazy_tls.Pointer()->Set(this);
  g_main_task_runner.Get() = message_loop_->task_runner();

  on_channel_error_called_ = false;

  OPENSSL_init_crypto(0, nullptr);

  grpc_init();
 // main_thread_runner_ = base::ThreadTaskRunnerHandle::Get();
#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  // We must make sure to instantiate the IPC Logger *before* we create the
  // channel, otherwise we can get a callback on the IO thread which creates
  // the logger, and the logger does not like being created on the IO thread.
  IPC::Logging::GetInstance();
#endif

  //ApplicationProcess* process = ApplicationProcess::current();
  //process->set_main_thread(this);
  channel_ = IPC::SyncChannel::Create(
      this, ApplicationProcess::current()->io_task_runner(),
      ipc_task_runner_ ? ipc_task_runner_ : base::ThreadTaskRunnerHandle::Get(),
      ApplicationProcess::current()->GetShutDownEvent());
#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  if (!IsInHostProcess())
    IPC::Logging::GetInstance()->SetIPCSender(this);
#endif

  std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation> invitation;
  mojo::ScopedMessagePipeHandle service_request_pipe;
  if (!IsInHostProcess()) {
    mojo_ipc_support_.reset(new mojo::edk::ScopedIPCSupport(
        GetIOTaskRunner(), mojo::edk::ScopedIPCSupport::ShutdownPolicy::FAST));
    invitation = InitializeMojoIPCChannel();

    std::string service_request_token =
        base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
            switches::kServiceRequestChannelToken);
      //". invitation? " << invitation;
    if (!service_request_token.empty() && invitation) {
      service_request_pipe =
          invitation->ExtractMessagePipe(service_request_token);
    }
  } else {
    service_request_pipe =
        options.broker_client_invitation->ExtractInProcessMessagePipe(
            options.in_process_service_request_token);
  }
  
  if (service_request_pipe.is_valid()) {
    service_manager_connection_ = common::ServiceManagerConnection::Create(
        service_manager::mojom::ServiceRequest(std::move(service_request_pipe)),
        GetIOTaskRunner());
  } else {
    LOG(ERROR) << "BAD: we couldnt connect with the service manager, therefore the service manager connection was not instantiated";
  }

  sync_message_filter_ = channel_->CreateSyncMessageFilter();
  
  thread_safe_sender_ =
      new ThreadSafeSender(main_thread_runner_, sync_message_filter_.get());

  resource_dispatcher_.reset(new ResourceDispatcher());

  InitializeV8IfNeeded();

  auto registry = std::make_unique<service_manager::BinderRegistry>();
  //registry->AddInterface(base::Bind(&ChildHistogramFetcherFactoryImpl::Create),
  //                       GetIOTaskRunner());
  binder_registry_ = registry.get();

  InitializeWebKit(resource_task_queue, binder_registry_);
  
  registry->AddInterface(base::Bind(&ApplicationThread::OnChildControlRequest,
                                    base::Unretained(this)),
                         base::ThreadTaskRunnerHandle::Get());

  GetServiceManagerConnection()->AddConnectionFilter(
      std::make_unique<common::SimpleConnectionFilter>(std::move(registry)));

  InitTracing();

  // In single process mode, browser-side tracing and memory will cover the
  // whole process including renderers.
  if (!IsInHostProcess()) {
    if (service_manager_connection_) {
      const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
      
      auto process_type = memory_instrumentation::mojom::ProcessType::OTHER;
      //if (command_line.HasSwitch(switches::kRendererProcess))
      //  process_type = memory_instrumentation::mojom::ProcessType::RENDERER;
      //else if (command_line.HasSwitch(switches::kGpuProcess))
      if (command_line.HasSwitch(switches::kGpuProcess)) {
        process_type = memory_instrumentation::mojom::ProcessType::GPU;
      } else if (command_line.HasSwitch(switches::kUtilityProcess)) {
        process_type = memory_instrumentation::mojom::ProcessType::UTILITY;
      }
    
      memory_instrumentation::ClientProcessImpl::Config config(
          GetConnector(), resource_coordinator::mojom::kServiceName,
          process_type);
      memory_instrumentation::ClientProcessImpl::CreateInstance(config);
    }
  }

  // In single process mode we may already have a power monitor,
  // also for some edge cases where there is no ServiceManagerConnection, we do
  // not create the power monitor.
  if (!base::PowerMonitor::Get() && service_manager_connection_) {
    auto power_monitor_source =
        std::make_unique<device::PowerMonitorBroadcastSource>(
            GetIOTaskRunner());
    auto* source_ptr = power_monitor_source.get();
    power_monitor_.reset(
        new base::PowerMonitor(std::move(power_monitor_source)));
    // The two-phase init is necessary to ensure that the process-wide
    // PowerMonitor is set before the power monitor source receives incoming
    // communication from the browser process (see https://crbug.com/821790 for
    // details)
    source_ptr->Init(GetConnector());
  }

#if defined(OS_POSIX)
  // Check that --process-type is specified so we don't do this in unit tests
  // and single-process mode.
  //const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
      
  //if (command_line.HasSwitch(switches::kGpuProcess) || 
  //  command_line.HasSwitch(switches::kApplicationProcess) || 
//    command_line.HasSwitch(switches::kShellProcess) ||
  //  command_line.HasSwitch(switches::kUtilityProcess)) {
    
    channel_->AddFilter(new SuicideOnChannelErrorFilter());
  //}
#endif

  // Add filters passed here via options.
  for (auto* startup_filter : options.startup_filters) {
    channel_->AddFilter(startup_filter);
  }

  ConnectChannel(invitation.get());

  // This must always be done after ConnectChannel, because ConnectChannel() may
  // add a ConnectionFilter to the connection.
  //if (options.auto_start_service_manager_connection &&
  //    service_manager_connection_) {
  if (service_manager_connection_) {
    StartServiceManagerConnection();
  }
  //}

  int connection_timeout = kConnectionTimeoutS;
  std::string connection_override =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          switches::kIPCConnectionTimeout);
  if (!connection_override.empty()) {
    int temp;
    if (base::StringToInt(connection_override, &temp))
      connection_timeout = temp;
  }

  main_thread_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ApplicationThread::EnsureConnected,
                     channel_connected_factory_->GetWeakPtr()),
      base::TimeDelta::FromSeconds(connection_timeout));

#if defined(OS_ANDROID)
  g_quit_closure.Get().BindToMainThread();
#endif

  // RenderThreadImpl-like init
  gpu_ = ui::Gpu::Create(GetConnector(),
                         base::FeatureList::IsEnabled(features::kMash)
                           ? ui::mojom::kServiceName
                           : common::mojom::kHostServiceName,
                         GetIOTaskRunner());

  webkit_shared_timer_suspended_ = false;
  widget_count_ = 0;
  // TODO: not supposed to be like this.. but the first time the window is shown
  //       the host is triggering the WindowRestored message (without a WindowHidden first)
  hidden_widget_count_ = 1;
  idle_notification_delay_in_ms_ = kInitialIdleHandlerDelayMs;
  idle_notifications_to_skip_ = 0;

  /*
   * Main impl start here
   */

  //auto registry = std::make_unique<service_manager::BinderRegistry>();

  //GetServiceManagerConnection()->AddConnectionFilter(
  //    std::make_unique<common::SimpleConnectionFilter>(std::move(registry)));

  //StartServiceManagerConnection();
  DCHECK(GetAssociatedInterfaceRegistry());

  GetAssociatedInterfaceRegistry()->AddInterface(
    base::BindRepeating(&ApplicationThread::OnApplicationInterfaceRequest,
      base::Unretained(this)));

  BindWindowDispatcher();

  LoadResourceBundles();

  // FIXME: we are using the name of the app as scheme now
  blink::WebSecurityPolicy::RegisterURLSchemeAsSupportingFetchAPI("app");

  vc_manager_.reset(new VideoCaptureImplManager());

//#if BUILDFLAG(ENABLE_WEBRTC)
  peer_connection_tracker_.reset(new PeerConnectionTracker());
  AddObserver(peer_connection_tracker_.get());

  p2p_socket_dispatcher_ = new P2PSocketDispatcher(GetIOTaskRunner().get());
  AddFilter(p2p_socket_dispatcher_.get());

  peer_connection_factory_.reset(
      new PeerConnectionDependencyFactory(p2p_socket_dispatcher_.get()));

  aec_dump_message_filter_ =
      new AecDumpMessageFilter(GetIOTaskRunner(), main_thread_runner());

  AddFilter(aec_dump_message_filter_.get());

  appcache_dispatcher_.reset(
      new AppCacheDispatcher(new AppCacheFrontendImpl()));
  binder_registry_->AddInterface(
      base::BindRepeating(&AppCacheDispatcher::Bind,
                          base::Unretained(appcache_dispatcher_.get())),
      GetIPCTaskRunner());
      //GetWebMainThreadScheduler()->IPCTaskRunner());
  file_system_dispatcher_.reset(new FileSystemDispatcher());

  notification_dispatcher_ = new NotificationDispatcher(
      thread_safe_sender(), GetIPCTaskRunner());//GetWebMainThreadScheduler()->IPCTaskRunner());
  AddFilter(notification_dispatcher_->GetFilter());

//#endif  // BUILDFLAG(ENABLE_WEBRTC)

  audio_input_ipc_factory_.emplace(main_thread_runner(), GetIOTaskRunner());

  audio_output_ipc_factory_.emplace(GetIOTaskRunner());

  midi_message_filter_ = new MidiMessageFilter(GetIOTaskRunner());
  AddFilter(midi_message_filter_.get());

  // Bind RouteRegistry
  channel()->GetRemoteAssociatedInterface(&route_registry_interface_);

  // Bind ChannelRegistry
  channel()->GetRemoteAssociatedInterface(&channel_registry_interface_);

  binder_registry_->AddInterface(
      base::BindRepeating(&EmbeddedWorkerInstanceClientImpl::Create,
                          base::TimeTicks::Now(), GetIOTaskRunner()),
      GetIPCTaskRunner());
      //GetWebMainThreadScheduler()->IPCTaskRunner());

  // automation
  //DLOG(INFO) << "ApplicationThread::Init: automation_context_->Init()";
  automation_context_.reset(new AutomationContext(channel(), window_dispatcher_.get(), GetServiceManagerConnection()));
  //blink::WebFrame* web_frame = window_dispatcher_->GetMainWebFrame(); 
  automation_context_->Init(binder_registry_, GetAssociatedInterfaceRegistry(), GetIPCTaskRunner());

  //url::AddCORSEnabledScheme(application_name_.c_str());
  url::AddStandardScheme(application_name_.c_str(), url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
  url::AddCSPBypassingScheme(application_name_.c_str());
  url::AddSecureScheme(application_name_.c_str());

  url::AddCSPBypassingScheme("rpc");
  url::AddSecureScheme("rpc");

  WTF::String app_scheme = WTF::String::FromUTF8(application_name_.c_str());

  blink::SchemeRegistry::RegisterURLSchemeAsSecure(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsCORSEnabled(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsAllowingServiceWorkers(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsSupportingFetchAPI(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeBypassingSecureContextCheck(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsAllowingWasmEvalCSP(app_scheme);
  //initialized_ = true;
}

void ApplicationThread::InitTracing() {
  // In single process mode, browser-side tracing and memory will cover the
  // whole process including renderers.
  if (IsInHostProcess())
    return;

  // Tracing adds too much overhead to the profiling service. The only
  // way to determine if this is the profiling service is by checking the
  // sandbox type.
  service_manager::SandboxType sandbox_type =
      service_manager::SandboxTypeFromCommandLine(
          *base::CommandLine::ForCurrentProcess());
  if (sandbox_type == service_manager::SANDBOX_TYPE_PROFILING)
    return;

  channel_->AddFilter(new tracing::ChildTraceMessageFilter(
      ApplicationProcess::current()->io_task_runner()));

  trace_event_agent_ = tracing::TraceEventAgent::Create(
      GetConnector(), false /* request_clock_sync_marker_on_android */);

  cc::SetClientNameForMetrics("Application");

  is_threaded_animation_enabled_ = true;
  is_zero_copy_enabled_ = true;
  is_partial_raster_enabled_ = true;
  is_gpu_memory_buffer_compositor_resources_enabled_ = true;
  is_elastic_overscroll_enabled_ = false;
#if defined(OS_ANDROID)
  is_lcd_text_enabled_ = false;
#else
  is_lcd_text_enabled_ = true;
#endif
  is_gpu_compositing_disabled_ = false;
  gpu_rasterization_msaa_sample_count_ = -1;

  media::InitializeMediaLibrary();

  int num_raster_threads = 2;

// #if defined(OS_LINUX)
//   categorized_worker_pool_->SetBackgroundingCallback(
//       main_thread_scheduler_->DefaultTaskRunner(),
//       base::BindOnce(
//           [](base::WeakPtr<ApplicationThread> render_thread,
//              base::PlatformThreadId thread_id) {
//             if (!render_thread)
//               return;
//             render_thread->render_message_filter()->SetThreadPriority(
//                 thread_id, base::ThreadPriority::BACKGROUND);
//           },
//           weak_factory_.GetWeakPtr()));
// #endif
  categorized_worker_pool_->Start(num_raster_threads);

  discardable_memory::mojom::DiscardableSharedMemoryManagerPtr manager_ptr;
  if (features::IsMusEnabled()) {
#if defined(USE_AURA)
    GetServiceManagerConnection()->GetConnector()->BindInterface(
        ui::mojom::kServiceName, &manager_ptr);
#else
    NOTREACHED();
#endif
  } else {
    GetConnector()->BindInterface(
        common::mojom::kHostServiceName, mojo::MakeRequest(&manager_ptr));
  }

  discardable_shared_memory_manager_ = std::make_unique<
      discardable_memory::ClientDiscardableSharedMemoryManager>(
      std::move(manager_ptr), GetIOTaskRunner());

  // TODO(boliu): In single process, browser main loop should set up the
  // discardable memory manager, and should skip this if kSingleProcess.
  // See crbug.com/503724.
  base::DiscardableMemoryAllocator::SetInstance(
      discardable_shared_memory_manager_.get());

  base::MemoryCoordinatorClientRegistry::GetInstance()->Register(this);

  GetConnector()->BindInterface(common::mojom::kHostServiceName,
                                mojo::MakeRequest(&frame_sink_provider_));

  if (!is_gpu_compositing_disabled_) {
    GetConnector()->BindInterface(
        common::mojom::kHostServiceName,
        mojo::MakeRequest(&compositing_mode_reporter_));

    // Make |this| a CompositingModeWatcher for the
    // |compositing_mode_reporter_|.
    viz::mojom::CompositingModeWatcherPtr watcher_ptr;
    compositing_mode_watcher_binding_.Bind(mojo::MakeRequest(&watcher_ptr));
    compositing_mode_reporter_->AddCompositingModeWatcher(
        std::move(watcher_ptr));
  }


}

ApplicationThread::~ApplicationThread() {
#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  IPC::Logging::GetInstance()->SetIPCSender(NULL);
#endif

  channel_->RemoveFilter(sync_message_filter_.get());

  // The ChannelProxy object caches a pointer to the IPC thread, so need to
  // reset it as it's not guaranteed to outlive this object.
  // NOTE: this also has the side-effect of not closing the main IPC channel to
  // the browser process.  This is needed because this is the signal that the
  // browser uses to know that this process has died, so we need it to be alive
  // until this process is shut down, and the OS closes the handle
  // automatically.  We used to watch the object handle on Windows to do this,
  // but it wasn't possible to do so on POSIX.
  channel_->ClearIPCTaskRunner();
  g_main_task_runner.Get() = nullptr;
  g_lazy_tls.Pointer()->Set(nullptr);
  
  //g_application_thread = nullptr;
}

void ApplicationThread::Shutdown() {
  // Delete objects that hold references to blink so derived classes can
  // safely shutdown blink in their Shutdown implementation.
  grpc_shutdown();
}

scoped_refptr<base::SingleThreadTaskRunner> ApplicationThread::DeprecatedGetMainTaskRunner() {
  return g_main_task_runner.Get();
}

void ApplicationThread::AddFilter(IPC::MessageFilter* filter) {
  channel()->AddFilter(filter);
}

common::CompositorHelper* ApplicationThread::compositor_helper() {
  return compositor_helper_.get();
}

common::mojom::RouteRegistry* ApplicationThread::GetRouteRegistry() {
  return route_registry_interface_.get();
}

common::mojom::ChannelRegistry* ApplicationThread::GetChannelRegistry() {
  return channel_registry_interface_.get();
}

bool ApplicationThread::ShouldBeDestroyed() {
  return true;
}

void ApplicationThread::SetResourceDispatcherDelegate(
    ResourceDispatcherDelegate* delegate) {
  resource_dispatcher_->set_delegate(delegate);
}

void ApplicationThread::CompositingModeFallbackToSoftware() {
  //DLOG(INFO) << "ApplicationThread::CompositingModeFallbackToSoftware";
  gpu_->LoseChannel();
  is_gpu_compositing_disabled_ = true;
}

void ApplicationThread::BindWindowDispatcher() { 
  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&ApplicationWindowDispatcher::BindApplicationWindow,
                          base::Unretained(window_dispatcher_.get())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&ApplicationWindowDispatcher::BindWindowInputHandler,
                        base::Unretained(window_dispatcher_.get())));

  DCHECK(channel());
  // bind remote window host
  channel()->GetRemoteAssociatedInterface(
    &window_dispatcher_->window_host_interface_);

  // bind the remote window input host
  channel()->GetRemoteAssociatedInterface(
    &window_dispatcher_->window_input_host_interface_);
}

void ApplicationThread::DestroyWindowDispatcher(ApplicationWindowDispatcher* window_dispatcher) {
 // for now is just this
  window_dispatcher_.reset();
}

bool ApplicationThread::IsGpuRasterizationForced() {
  return is_gpu_rasterization_forced_;
}

int ApplicationThread::GetGpuRasterizationMSAASampleCount() {
  return gpu_rasterization_msaa_sample_count_;
}

bool ApplicationThread::IsLcdTextEnabled() {
  return is_lcd_text_enabled_;
}

bool ApplicationThread::IsZeroCopyEnabled() {
  return is_zero_copy_enabled_;
}

bool ApplicationThread::IsPartialRasterEnabled() {
  return is_partial_raster_enabled_;
}

bool ApplicationThread::IsGpuMemoryBufferCompositorResourcesEnabled() {
  return is_gpu_memory_buffer_compositor_resources_enabled_;
}

bool ApplicationThread::IsElasticOverscrollEnabled() {
  return is_elastic_overscroll_enabled_;
}

scoped_refptr<base::SingleThreadTaskRunner> ApplicationThread::GetCompositorMainThreadTaskRunner() {
  DCHECK(main_thread_compositor_task_runner_);
  return main_thread_compositor_task_runner_;  
}

scoped_refptr<base::SingleThreadTaskRunner> ApplicationThread::GetCompositorImplThreadTaskRunner() {
  DCHECK(compositor_task_runner_);
  return compositor_task_runner_;
}

blink::scheduler::WebMainThreadScheduler* ApplicationThread::GetWebMainThreadScheduler() {
  DCHECK(main_thread_scheduler_);
  return main_thread_scheduler_.get();
}

viz::SharedBitmapManager* ApplicationThread::GetSharedBitmapManager()  {
  // Assert compositor shims from sdk never call this when using application thread
  // as compositor dependencies 
  // (aka remote renderer/ not single-threaded compositor)
  DCHECK(false);
  return nullptr;
}

gpu::ImageFactory* ApplicationThread::GetImageFactory() {
 // Assert compositor shims from sdk never call this when using application thread
 // as compositor dependencies 
 // (aka remote renderer/ not single-threaded compositor) 
 DCHECK(false);
 return nullptr;
}

std::unique_ptr<viz::SyntheticBeginFrameSource> ApplicationThread::CreateSyntheticBeginFrameSource() {
  base::SingleThreadTaskRunner* compositor_impl_side_task_runner =
      compositor_task_runner_ ? compositor_task_runner_.get()
                              : base::ThreadTaskRunnerHandle::Get().get();
  return std::make_unique<viz::BackToBackBeginFrameSource>(
      std::make_unique<viz::DelayBasedTimeSource>(
          compositor_impl_side_task_runner));
}

int ApplicationThread::GenerateRoutingID() {
  return window_dispatcher()->GenerateRoutingID();
}

std::unique_ptr<cc::SwapPromise> ApplicationThread::QueueVisualStateResponse(int32_t source_frame_number, uint64_t id) {
  bool first_message_for_frame = false;
  frame_swap_message_queue_->QueueMessageForFrame(MESSAGE_DELIVERY_POLICY_WITH_VISUAL_STATE, 
                                                 source_frame_number,
                                                 base::WrapUnique(new FrameHostMsg_VisualStateResponse(routing_id_, id)),
                                                 &first_message_for_frame);
  if (first_message_for_frame) {
    std::unique_ptr<cc::SwapPromise> promise(new QueueMessageSwapPromise(
        sync_message_filter_, frame_swap_message_queue_, source_frame_number));
    return promise;
  }
  return nullptr;
}

scoped_refptr<ui::ContextProviderCommandBuffer> ApplicationThread::SharedMainThreadContextProvider() {
  DCHECK(IsMainThread());
  if (shared_main_thread_contexts_ &&
      shared_main_thread_contexts_->ContextGL()->GetGraphicsResetStatusKHR() ==
          GL_NO_ERROR)
    return shared_main_thread_contexts_;

  scoped_refptr<gpu::GpuChannelHost> gpu_channel_host(
      EstablishGpuChannelSync());
  if (!gpu_channel_host) {
    shared_main_thread_contexts_ = nullptr;
    return nullptr;
  }

  bool support_locking = false;
  bool support_gles2_interface = true;
  bool support_raster_interface = false;
  bool support_oop_rasterization = false;
  bool support_grcontext = true;
  shared_main_thread_contexts_ = CreateOffscreenContext(
      std::move(gpu_channel_host), GetGpuMemoryBufferManager(),
      gpu::SharedMemoryLimits(), support_locking, support_gles2_interface,
      support_raster_interface, support_oop_rasterization, support_grcontext,
      ui::command_buffer_metrics::RENDERER_MAINTHREAD_CONTEXT,
      common::kGpuStreamIdDefault, common::kGpuStreamPriorityDefault);
  auto result = shared_main_thread_contexts_->BindToCurrentThread();
  if (result != gpu::ContextResult::kSuccess)
    shared_main_thread_contexts_ = nullptr;
  return shared_main_thread_contexts_;
}

cc::TaskGraphRunner* ApplicationThread::GetTaskGraphRunner() {
  DCHECK(categorized_worker_pool_->GetTaskGraphRunner());
  return categorized_worker_pool_->GetTaskGraphRunner();
}

bool ApplicationThread::IsThreadedAnimationEnabled() {
  return is_threaded_animation_enabled_;
}

bool ApplicationThread::IsScrollAnimatorEnabled() {
  return is_scroll_animator_enabled_;
}

std::unique_ptr<cc::UkmRecorderFactory> ApplicationThread::CreateUkmRecorderFactory() {
  return std::make_unique<UkmRecorderFactoryImpl>(GetConnector()->Clone());
}

void ApplicationThread::InitializeWebKit(
    const scoped_refptr<base::SingleThreadTaskRunner>& resource_task_queue,
    service_manager::BinderRegistry* registry) {
  DCHECK(!blink_platform_impl_);

//  const base::CommandLine& command_line =
//      *base::CommandLine::ForCurrentProcess();

  blink_platform_impl_.reset(
      new BlinkPlatformImpl(this, main_thread_scheduler_.get(), app_callbacks_, instance_state_));
  //SetRuntimeFeaturesDefaultsAndUpdateFromArgs(command_line);
  //common::GetClient()
  //    ->renderer()
  //    ->SetRuntimeFeaturesDefaultsBeforeBlinkInitialization();
  blink::Initialize(blink_platform_impl_.get(), registry);
  //v8::Isolate* isolate = blink::MainThreadIsolate();
  //isolate->SetCreateHistogramFunction(CreateHistogram);
  //isolate->SetAddHistogramSampleFunction(AddHistogramSample);
  //main_thread_scheduler_->SetRAILModeObserver(this);
  DCHECK(main_thread_scheduler_);
  main_thread_compositor_task_runner_ =
      main_thread_scheduler_->CompositorTaskRunner();
  DCHECK(main_thread_compositor_task_runner_);

  //DLOG(INFO) << "ApplicationThread::InitializeWebKit: InitializeCompositorThread()";
  InitializeCompositorThread();

  //scoped_refptr<base::SingleThreadTaskRunner> compositor_impl_side_task_runner;
  //if (compositor_task_runner_)
  //  compositor_impl_side_task_runner = compositor_task_runner_;
  //else
  //  compositor_impl_side_task_runner = base::ThreadTaskRunnerHandle::Get();

  //RenderMediaClient::Initialize();
  DCHECK(GetWebMainThreadScheduler());
  idle_timer_.SetTaskRunner(GetWebMainThreadScheduler()->DefaultTaskRunner());

  ScheduleIdleHandler(kLongIdleHandlerDelayMs);

  main_thread_scheduler_->SetFreezingWhenBackgroundedEnabled(false);
      //common::GetClient()->renderer()->AllowFreezingWhenProcessBackgrounded());

  SkGraphics::SetResourceCacheSingleAllocationByteLimit(
      kImageCacheSingleAllocationByteLimit);

  // Hook up blink's codecs so skia can call them
  SkGraphics::SetImageGeneratorFromEncodedDataFactory(
      blink::WebImageGenerator::CreateAsSkImageGenerator);

  //if (command_line.HasSwitch(switches::kExplicitlyAllowedPorts)) {
  //  std::string allowed_ports =
  //      command_line.GetSwitchValueASCII(switches::kExplicitlyAllowedPorts);
  //  net::SetExplicitlyAllowedPorts(allowed_ports);
  //}
  service_worker_message_filter_ = new ServiceWorkerMessageFilter(
      thread_safe_sender(), GetIPCTaskRunner());//GetWebMainThreadScheduler()->IPCTaskRunner());
  AddFilter(service_worker_message_filter_->GetFilter());
}

void ApplicationThread::InitializeCompositorThread() {
  blink::WebThreadCreationParams params(
      blink::WebThreadType::kCompositorThread);
//#if defined(OS_ANDROID)
  params.thread_options.priority = base::ThreadPriority::DISPLAY;
//#endif
  compositor_thread_ =
      blink::scheduler::WebThreadBase::CreateCompositorThread(params);
  blink_platform_impl_->SetCompositorThread(compositor_thread_.get());
  compositor_task_runner_ = compositor_thread_->GetTaskRunner();
  DCHECK(compositor_task_runner_);
  compositor_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(base::IgnoreResult(&base::ThreadRestrictions::SetIOAllowed),
                     false));
  //common::GetClient()->renderer()->PostCompositorThreadCreated(
  //    compositor_task_runner_.get());
//#if defined(OS_LINUX)
  //render_message_filter()->SetThreadPriority(compositor_thread_->ThreadId(),
  //                                           base::ThreadPriority::DISPLAY);
//#endif

}

std::unique_ptr<base::SharedMemory> ApplicationThread::HostAllocateSharedMemoryBuffer(size_t size) {
  return ApplicationThread::AllocateSharedMemory(size);
}

void ApplicationThread::ScheduleIdleHandler(int64_t initial_delay_ms) {
  idle_notification_delay_in_ms_ = initial_delay_ms;
  idle_timer_.Stop();
  idle_timer_.Start(FROM_HERE,
      base::TimeDelta::FromMilliseconds(initial_delay_ms),
      this, &ApplicationThread::IdleHandler);
}

void ApplicationThread::IdleHandler() {
  bool run_in_foreground_tab = (widget_count_ > hidden_widget_count_);
  if (run_in_foreground_tab) {
    if (idle_notifications_to_skip_ > 0) {
      --idle_notifications_to_skip_;
    } else {
      ReleaseFreeMemory();
    }
    ScheduleIdleHandler(kLongIdleHandlerDelayMs);
    return;
  }

  ReleaseFreeMemory();

  // Continue the idle timer if the webkit shared timer is not suspended or
  // something is left to do.
  bool continue_timer = !webkit_shared_timer_suspended_;

  // Schedule next invocation. When the tab is originally hidden, an invocation
  // is scheduled for kInitialIdleHandlerDelayMs in
  // RenderThreadImpl::WidgetHidden in order to race to a minimal heap.
  // After that, idle calls can be much less frequent, so run at a maximum of
  // once every kLongIdleHandlerDelayMs.
  // Dampen the delay using the algorithm (if delay is in seconds):
  //    delay = delay + 1 / (delay + 2)
  // Using floor(delay) has a dampening effect such as:
  //    30s, 30, 30, 31, 31, 31, 31, 32, 32, ...
  // If the delay is in milliseconds, the above formula is equivalent to:
  //    delay_ms / 1000 = delay_ms / 1000 + 1 / (delay_ms / 1000 + 2)
  // which is equivalent to
  //    delay_ms = delay_ms + 1000*1000 / (delay_ms + 2000).
  if (continue_timer) {
    ScheduleIdleHandler(
        std::max(kLongIdleHandlerDelayMs,
                 idle_notification_delay_in_ms_ +
                 1000000 / (idle_notification_delay_in_ms_ + 2000)));

  } else {
    idle_timer_.Stop();
  }

  //for (auto& observer : observers_)
  //  observer.IdleNotification();
}

void ApplicationThread::ReleaseFreeMemory() {
  base::allocator::ReleaseFreeMemory();
  discardable_shared_memory_manager_->ReleaseFreeMemory();

  // Do not call into blink if it is not initialized.
  if (blink_platform_impl_) {
    // Purge Skia font cache, resource cache, and image filter.
    SkGraphics::PurgeAllCaches();
    blink::DecommitFreeableMemory();
  }
}

gpu::GpuChannelHost* ApplicationThread::GetGpuChannel() {
  return gpu_->GetGpuChannel().get();
}

base::TaskRunner* ApplicationThread::GetWorkerTaskRunner() {
  return categorized_worker_pool_.get();
}

scoped_refptr<viz::RasterContextProvider> ApplicationThread::SharedCompositorWorkerContextProvider() {
  DCHECK(IsMainThread());
  // Try to reuse existing shared worker context provider.
  if (shared_worker_context_provider_) {
    // Note: If context is lost, delete reference after releasing the lock.
    viz::RasterContextProvider::ScopedRasterContextLock lock(
        shared_worker_context_provider_.get());
    if (lock.RasterInterface()->GetGraphicsResetStatusKHR() == GL_NO_ERROR)
      return shared_worker_context_provider_;
  }

  scoped_refptr<gpu::GpuChannelHost> gpu_channel_host(
      EstablishGpuChannelSync());
  if (!gpu_channel_host) {
    shared_worker_context_provider_ = nullptr;
    return shared_worker_context_provider_;
  }

  bool support_locking = true;
  bool support_oop_rasterization = false;
      //base::CommandLine::ForCurrentProcess()->HasSwitch(
      //    switches::kEnableOOPRasterization);
  bool support_gles2_interface = !support_oop_rasterization;
  bool support_raster_interface = true;
  bool support_grcontext = !support_oop_rasterization;
  shared_worker_context_provider_ = CreateOffscreenContext(
      std::move(gpu_channel_host), GetGpuMemoryBufferManager(),
      gpu::SharedMemoryLimits(), support_locking, support_gles2_interface,
      support_raster_interface, support_oop_rasterization, support_grcontext,
      ui::command_buffer_metrics::RENDER_WORKER_CONTEXT, common::kGpuStreamIdWorker,
      common::kGpuStreamPriorityWorker);
  auto result = shared_worker_context_provider_->BindToCurrentThread();
  if (result != gpu::ContextResult::kSuccess)
    shared_worker_context_provider_ = nullptr;
  return shared_worker_context_provider_;
}

void ApplicationThread::OnChannelConnected(int32_t peer_pid) {
  channel_connected_factory_.reset();
}

void ApplicationThread::OnChannelError() {
  on_channel_error_called_ = true;
  // If this thread runs in the browser process, only Thread::Stop should
  // stop its message loop. Otherwise, QuitWhenIdle could race Thread::Stop.
  if (!IsInHostProcess())
    base::RunLoop::QuitCurrentWhenIdleDeprecated();
}

bool ApplicationThread::Send(IPC::Message* msg) {
  DCHECK(main_thread_runner_->BelongsToCurrentThread());
  if (!channel_) {
    delete msg;
    return false;
  }

  return channel_->Send(msg);
}

#if defined(OS_WIN)
void ApplicationThread::PreCacheFont(const LOGFONT& log_font) {
  GetFontCacheWin()->PreCacheFont(log_font);
}

void ApplicationThread::ReleaseCachedFonts() {
  GetFontCacheWin()->ReleaseCachedFonts();
}

common::mojom::FontCacheWin* ApplicationThread::GetFontCacheWin() {
  if (!font_cache_win_ptr_) {
    GetConnector()->BindInterface(common::mojom::kHostServiceName,
                                  &font_cache_win_ptr_);
  }
  return font_cache_win_ptr_.get();
}
#elif defined(OS_MACOSX)
bool ApplicationThread::LoadFont(const base::string16& font_name,
                               float font_point_size,
                               mojo::ScopedSharedBufferHandle* out_font_data,
                               uint32_t* out_font_id) {
  return GetFontLoaderMac()->LoadFont(font_name, font_point_size, out_font_data,
                                      out_font_id);
}

common::mojom::FontLoaderMac* ApplicationThread::GetFontLoaderMac() {
  if (!font_loader_mac_ptr_) {
    GetConnector()->BindInterface(common::mojom::kHostServiceName,
                                  &font_loader_mac_ptr_);
  }
  return font_loader_mac_ptr_.get();
}
#endif

common::ServiceManagerConnection* ApplicationThread::GetServiceManagerConnection() {
  return service_manager_connection_.get();
}

service_manager::Connector* ApplicationThread::GetConnector() {
  return service_manager_connection_->GetConnector();
}

IPC::MessageRouter* ApplicationThread::GetRouter() {
  DCHECK(main_thread_runner_->BelongsToCurrentThread());
  return &router_;
}

common::mojom::RouteProvider* ApplicationThread::GetRemoteRouteProvider() {
  if (!remote_route_provider_) {
    DCHECK(channel_);
    channel_->GetRemoteAssociatedInterface(&remote_route_provider_);
  }
  return remote_route_provider_.get();
}

// static
std::unique_ptr<base::SharedMemory> ApplicationThread::AllocateSharedMemory(
    size_t buf_size) {
  mojo::ScopedSharedBufferHandle mojo_buf =
      mojo::SharedBufferHandle::Create(buf_size);
  if (!mojo_buf->is_valid()) {
    LOG(WARNING) << "Host failed to allocate shared memory";
    return nullptr;
  }

  base::SharedMemoryHandle shared_buf;
  if (mojo::UnwrapSharedMemoryHandle(std::move(mojo_buf), &shared_buf,
                                     nullptr, nullptr) != MOJO_RESULT_OK) {
    LOG(WARNING) << "Host failed to allocate shared memory";
    return nullptr;
  }

  return std::make_unique<base::SharedMemory>(shared_buf, false);
}

bool ApplicationThread::OnMessageReceived(const IPC::Message& msg) {
  if (file_system_dispatcher_->OnMessageReceived(msg)) {
    return true;
  }
  if (msg.routing_id() == MSG_ROUTING_CONTROL)
    return OnControlMessageReceived(msg);

  return router_.OnMessageReceived(msg);
}

void ApplicationThread::OnAssociatedInterfaceRequest(
    const std::string& name,
    mojo::ScopedInterfaceEndpointHandle handle) {
  
  if (associated_interfaces_.CanBindRequest(name)) {
    associated_interfaces_.BindRequest(name, std::move(handle));
  } else {
    if (name == common::mojom::RouteProvider::Name_) {
      DCHECK(!route_provider_binding_.is_bound());
      route_provider_binding_.Bind(
          common::mojom::RouteProviderAssociatedRequest(std::move(handle)),
          ipc_task_runner_ ? ipc_task_runner_
                           : base::ThreadTaskRunnerHandle::Get());
    } //else {
    //  LOG(ERROR) << "Request for unknown Channel-associated interface: "
    //             << name;
    //}
  }
}

void ApplicationThread::StartServiceManagerConnection() {
  DCHECK(service_manager_connection_);
  service_manager_connection_->Start();
  common::GetClient()->OnServiceManagerConnected(
      service_manager_connection_.get());
}

void ApplicationThread::AddObserver(ApplicationThreadObserver* observer) {
  observers_.AddObserver(observer);
  observer->RegisterMojoInterfaces(&associated_interfaces_);
}

void ApplicationThread::RemoveObserver(ApplicationThreadObserver* observer) {
  observer->UnregisterMojoInterfaces(&associated_interfaces_);
  observers_.RemoveObserver(observer);
}

bool ApplicationThread::OnControlMessageReceived(const IPC::Message& msg) {
  for (auto& observer : observers_) {
    if (observer.OnControlMessageReceived(msg))
      return true;
  }

  return false;
}

void ApplicationThread::ProcessShutdown() {
  base::RunLoop::QuitCurrentWhenIdleDeprecated();
}

#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
void ApplicationThread::SetIPCLoggingEnabled(bool enable) {
  if (enable)
    IPC::Logging::GetInstance()->Enable();
  else
    IPC::Logging::GetInstance()->Disable();
}
#endif  //  IPC_MESSAGE_LOG_ENABLED

void ApplicationThread::OnChildControlRequest(
    common::mojom::ChildControlRequest request) {
  child_control_bindings_.AddBinding(this, std::move(request));
}

ApplicationThread* ApplicationThread::current() {
  return g_lazy_tls.Pointer()->Get();
  //DLOG(INFO) << "ApplicationThread::current: g_application_thread = " << g_application_thread;
  //return g_application_thread;
}

#if defined(OS_ANDROID)
// The method must NOT be called on the child thread itself.
// It may block the child thread if so.
void ApplicationThread::ShutdownThread() {
  DCHECK(!ApplicationThread::current()) <<
      "this method should NOT be called from child thread itself";
  g_quit_closure.Get().PostQuitFromNonMainThread();
}
#endif

void ApplicationThread::OnProcessFinalRelease() {
  if (on_channel_error_called_)
    return;

  GetApplicationHost()->ShutdownRequest();

  ProcessShutdown();
}

void ApplicationThread::EnsureConnected() {
  VLOG(0) << "ApplicationThread::EnsureConnected()";
  base::Process::TerminateCurrentProcessImmediately(0);
}

void ApplicationThread::GetRoute(
    int32_t routing_id,
    common::mojom::AssociatedInterfaceProviderAssociatedRequest request) {
  associated_interface_provider_bindings_.AddBinding(
      this, std::move(request), routing_id);
}

void ApplicationThread::GetAssociatedInterface(
    const std::string& name,
    common::mojom::AssociatedInterfaceAssociatedRequest request) {
  int32_t routing_id =
      associated_interface_provider_bindings_.dispatch_context();
  Listener* route = router_.GetRoute(routing_id);
  if (route)
    route->OnAssociatedInterfaceRequest(name, request.PassHandle());
}

common::mojom::RendererAudioInputStreamFactory*
ApplicationThread::GetAudioInputStreamFactoryForFrame(int frame_id) {
  common::mojom::RendererAudioInputStreamFactory* factory;
  auto it = audio_input_stream_factories_.find(frame_id);
  if (it == audio_input_stream_factories_.end()) {
    common::mojom::RendererAudioInputStreamFactoryPtr new_factory;
    GetRemoteInterfaces()->GetInterface(&new_factory);
    factory = new_factory.get();
    audio_input_stream_factories_.emplace(std::make_pair(frame_id, std::move(new_factory)));
  } else {
    factory = it->second.get();
  }
  return factory;
}

bool ApplicationThread::IsInHostProcess() const {
  return static_cast<bool>(host_process_io_runner_);
}

common::mojom::ApplicationHost* ApplicationThread::GetApplicationHost() {
  if (!application_host_) {
    channel()->GetRemoteAssociatedInterface(&application_host_);
  }
  return application_host_.get();
}

void ApplicationThread::CreateEmbedderApplicationService(
    service_manager::mojom::ServiceRequest service_request) {
 service_context_ = std::make_unique<service_manager::ServiceContext>(
      std::make_unique<service_manager::ForwardingService>(this),
      std::move(service_request));
}

void ApplicationThread::GetHandle(GetHandleCallback callback) {
  //DLOG(INFO) << "ApplicationThread::GetHandle: not implemented";
}

void ApplicationThread::CreateNewWindow(common::mojom::CreateNewWindowParamsPtr params) {
  //DLOG(INFO) << "ApplicationThread::CreateNewWindow: getting new remote_interfaces_";

  //int child_routing_id = MSG_ROUTING_NONE;
  //mojo::MessagePipeHandle child_interface_provider_handle;
  
  //FrameHostMsg_CreateNewWindow_Params window_params;
  //window_params.parent_routing_id = routing_id_;
  //params.scope = scope;
  //window_params.frame_name = params->window_name;
  //window_params.is_created_by_script = false;
  //window_params.frame_unique_name = params->window_name;
  //frame_params.frame_policy = {sandbox_flags, container_policy};
  //frame_params.frame_owner_properties =
  //    ConvertWebFrameOwnerPropertiesToFrameOwnerProperties(
  //        frame_owner_properties);
  //Send(new FrameHostMsg_CreateNewWindow(window_params, &child_routing_id,
  //                                      &child_interface_provider_handle));

  // Allocation of routing id failed, so we can't create a child frame. This can
  // happen if the synchronous IPC message above has failed.  This can
  // legitimately happen when the browser process has already destroyed
  // RenderProcessHost, but the renderer process hasn't quit yet.
  //if (child_routing_id == MSG_ROUTING_NONE)
  //  return nullptr;

  CHECK(params->interface_provider.is_valid());
  service_manager::mojom::InterfaceProviderPtr main_frame_interface_provider(
        std::move(params->interface_provider));
  remote_interfaces_.Bind(std::move(main_frame_interface_provider));
  //service_manager::mojom::InterfaceProviderPtr child_interface_provider;
  //child_interface_provider.Bind(
  //    service_manager::mojom::InterfaceProviderPtrInfo(
  //        mojo::ScopedMessagePipeHandle(child_interface_provider_handle), 0u),
  //    GetTaskRunner(blink::TaskType::kInternalIPC));
      //GetIOTaskRunner());
  
  //service_manager::mojom::InterfaceProviderPtr interfaces_provider;
  //service_manager::mojom::InterfaceProviderRequest 
  //  remote_interface_provider_request = mojo::MakeRequest(&interfaces_provider);
  //remote_interfaces_.Bind(std::move(interfaces_provider));

  auto* audio_factory = AudioOutputIPCFactory::get();
  DCHECK(audio_factory);

  // With service interface [indirect]
  audio_factory->RegisterRemoteFactory(routing_id_, GetRemoteInterfaces());
  
  // With factory [direct]
  //CHECK(params->audio_output_stream_factory.is_valid());
  //audio_factory->RegisterRemoteFactory(routing_id_, std::move(params->audio_output_stream_factory));
  
  main_thread_runner_->PostTask(FROM_HERE,
    base::BindOnce(&ApplicationThread::CreateNewWindowImpl, base::Unretained(this), base::Passed(std::move(params))));
}

void ApplicationThread::CreateNewWindowImpl(common::mojom::CreateNewWindowParamsPtr params) {
    //DLOG(INFO) << "ApplicationThread::CreateNewWindow: not implemented"; 
  // TODO: now that we have a "ApplicationInstance" object on hte kit side (swift/cpp)
  //       we can just pass to a given callback so they can handle this
  //       via ApplicationInstance
  app_callbacks_.CreateNewWindow(
     instance_state_,
     params->initial_size.local_surface_id->parent_sequence_number(),
     params->initial_size.local_surface_id->child_sequence_number(),
     params->initial_size.local_surface_id->embed_token().GetHighForSerialization(), 
     params->initial_size.local_surface_id->embed_token().GetLowForSerialization(),
     params->initial_size.screen_info.device_scale_factor,
     params->initial_size.screen_info.depth,
     params->initial_size.screen_info.depth_per_component,
     params->initial_size.screen_info.is_monochrome,
     params->initial_size.screen_info.rect.x(),
     params->initial_size.screen_info.rect.y(),
     params->initial_size.screen_info.rect.width(),
     params->initial_size.screen_info.rect.height(),
     params->initial_size.screen_info.available_rect.x(),
     params->initial_size.screen_info.available_rect.y(),
     params->initial_size.screen_info.available_rect.width(),
     params->initial_size.screen_info.available_rect.height(),
     params->initial_size.screen_info.orientation_type,
     params->initial_size.screen_info.orientation_angle,
     params->initial_size.auto_resize_enabled, 
     params->initial_size.min_size_for_auto_resize.width(), 
     params->initial_size.min_size_for_auto_resize.height(), 
     params->initial_size.max_size_for_auto_resize.width(), 
     params->initial_size.max_size_for_auto_resize.height(),
     params->initial_size.new_size.width(),
     params->initial_size.new_size.height(),
     params->initial_size.compositor_viewport_pixel_size.width(),
     params->initial_size.compositor_viewport_pixel_size.height(),
     params->initial_size.visible_viewport_size.width(),
     params->initial_size.visible_viewport_size.height(),
     params->initial_size.capture_sequence_number);
}

//service_manager::Connector* ApplicationThread::GetConnector() {
//  if (!connector_)
//    connector_ = service_manager::Connector::Create(&connector_request_);
//  return connector_.get();
//}

void ApplicationThread::OnStart() {
  context()->connector()->BindConnectorRequest(std::move(connector_request_));
}

void ApplicationThread::OnBindInterface(
    const service_manager::BindSourceInfo& remote_info,
    const std::string& name,
    mojo::ScopedMessagePipeHandle handle) {
  //registry_.TryBindInterface(name, &handle);
  binder_registry_->TryBindInterface(name, &handle);
}

void ApplicationThread::BindLocalInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  GetInterface(interface_name, std::move(interface_pipe));
}

service_manager::InterfaceProvider* ApplicationThread::GetRemoteInterfaces() {
  return &remote_interfaces_;
}

blink::AssociatedInterfaceRegistry*
ApplicationThread::GetAssociatedInterfaceRegistry() {
  return &associated_interfaces_;
}

blink::AssociatedInterfaceProvider*
ApplicationThread::GetRemoteAssociatedInterfaces() {
  if (!remote_associated_interfaces_) {
    common::mojom::AssociatedInterfaceProviderAssociatedPtr remote_interfaces;
    GetRemoteRouteProvider()->GetRoute(
        routing_id_, mojo::MakeRequest(&remote_interfaces));
    remote_associated_interfaces_.reset(new common::AssociatedInterfaceProviderImpl(
        std::move(remote_interfaces),
        GetIPCTaskRunner()));
  }
  return remote_associated_interfaces_.get();
}

bool ApplicationThread::IsEncryptedMediaEnabled() const {
  //return GetRendererPreferences().enable_encrypted_media;
  return true;
}

AudioRendererMixerManager* ApplicationThread::GetAudioRendererMixerManager() {
  if (!audio_renderer_mixer_manager_) {
    audio_renderer_mixer_manager_ = AudioRendererMixerManager::Create();
  }

  return audio_renderer_mixer_manager_.get();
}

void ApplicationThread::GetInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  // In some tests, this may not be configured.
  //if (!connector_)
  //  return;
  connector_->BindInterface(
      service_manager::Identity(common::mojom::kApplicationServiceName), interface_name,
      std::move(interface_pipe));
}

void ApplicationThread::OnApplicationInterfaceRequest(
    common::mojom::ApplicationAssociatedRequest request) {
  DCHECK(!application_binding_.is_bound());
  application_binding_.Bind(std::move(request));
}

scoped_refptr<gpu::GpuChannelHost> ApplicationThread::EstablishGpuChannelSync() {
  TRACE_EVENT0("gpu", "RenderThreadImpl::EstablishGpuChannelSync");

  scoped_refptr<gpu::GpuChannelHost> gpu_channel =
      gpu_->EstablishGpuChannelSync();
  if (gpu_channel)
    common::GetClient()->SetGpuInfo(gpu_channel->gpu_info());
  return gpu_channel;
}

// void ApplicationThread::RequestNewLayerTreeFrameSink(
//     int routing_id,
//     scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue,
//     const GURL& url,
//     const LayerTreeFrameSinkCallback& callback,
//     common::mojom::RenderFrameMetadataObserverClientRequest
//         render_frame_metadata_observer_client_request,
//     common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer_ptr) {

//   const base::CommandLine& command_line =
//       *base::CommandLine::ForCurrentProcess();
//   viz::ClientLayerTreeFrameSink::InitParams params;
//   params.compositor_task_runner = compositor_task_runner_;
//   params.enable_surface_synchronization =
//       features::IsSurfaceSynchronizationEnabled();
//   params.local_surface_id_provider =
//       std::make_unique<ApplicationLocalSurfaceIdProvider>();
//   if (features::IsVizHitTestingDrawQuadEnabled()) {
//     params.hit_test_data_provider =
//         std::make_unique<viz::HitTestDataProviderDrawQuad>(
//             true /* should_ask_for_child_region */);
//   } else if (features::IsVizHitTestingSurfaceLayerEnabled()) {
//     params.hit_test_data_provider =
//         std::make_unique<viz::HitTestDataProviderSurfaceLayer>();
//   }

//   // The renderer runs animations and layout for animate_only BeginFrames.
//   params.wants_animate_only_begin_frames = true;

//   // In disable gpu vsync mode, also let the renderer tick as fast as it
//   // can. The top level begin frame source will also be running as a back
//   // to back begin frame source, but using a synthetic begin frame source
//   // here reduces latency when in this mode (at least for frames
//   // starting--it potentially increases it for input on the other hand.)
//   if (command_line.HasSwitch(switches::kDisableGpuVsync) &&
//       command_line.GetSwitchValueASCII(switches::kDisableGpuVsync) != "gpu") {
//     params.synthetic_begin_frame_source = CreateSyntheticBeginFrameSource();
//   }

// // #if defined(USE_AURA)
// //   if (base::FeatureList::IsEnabled(features::kMash)) {
// //     if (!ApplicationWindowTreeClient::Get(routing_id)) {
// //       callback.Run(nullptr);
// //       return;
// //     }
// //     scoped_refptr<gpu::GpuChannelHost> channel = EstablishGpuChannelSync();
// //     // If the channel could not be established correctly, then return null. This
// //     // would cause the compositor to wait and try again at a later time.
// //     if (!channel) {
// //       callback.Run(nullptr);
// //       return;
// //     }
// //     ApplicationWindowTreeClient::Get(routing_id)
// //         ->RequestLayerTreeFrameSink(
// //             gpu_->CreateContextProvider(std::move(channel)),
// //             GetGpuMemoryBufferManager(), callback);
// //     return;
// //   }
// // #endif

//   viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request =
//       mojo::MakeRequest(&params.pipes.compositor_frame_sink_info);
//   viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client;
//   params.pipes.client_request =
//       mojo::MakeRequest(&compositor_frame_sink_client);

//   if (is_gpu_compositing_disabled_) {
//     DCHECK(!layout_test_mode());
//     frame_sink_provider_->CreateForWidget(
//         routing_id, std::move(compositor_frame_sink_request),
//         std::move(compositor_frame_sink_client),
//         std::move(render_frame_metadata_observer_client_request),
//         std::move(render_frame_metadata_observer_ptr));
//     callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
//         nullptr, nullptr, &params));
//     return;
//   }

//   scoped_refptr<gpu::GpuChannelHost> gpu_channel_host =
//       EstablishGpuChannelSync();
//   if (!gpu_channel_host) {
//     // Wait and try again. We may hear that the compositing mode has switched
//     // to software in the meantime.
//     callback.Run(nullptr);
//     return;
//   }

//   scoped_refptr<viz::RasterContextProvider> worker_context_provider =
//       SharedCompositorWorkerContextProvider();
//   if (!worker_context_provider) {
//     // Cause the compositor to wait and try again.
//     callback.Run(nullptr);
//     return;
//   }

//   // The renderer compositor context doesn't do a lot of stuff, so we don't
//   // expect it to need a lot of space for commands or transfer. Raster and
//   // uploads happen on the worker context instead.
//   gpu::SharedMemoryLimits limits = gpu::SharedMemoryLimits::ForMailboxContext();

//   // This is for an offscreen context for the compositor. So the default
//   // framebuffer doesn't need alpha, depth, stencil, antialiasing.
//   gpu::ContextCreationAttribs attributes;
//   attributes.alpha_size = -1;
//   attributes.depth_size = 0;
//   attributes.stencil_size = 0;
//   attributes.samples = 0;
//   attributes.sample_buffers = 0;
//   attributes.bind_generates_resource = false;
//   attributes.lose_context_when_out_of_memory = true;
//   attributes.enable_gles2_interface = true;
//   attributes.enable_raster_interface = false;
//   attributes.enable_oop_rasterization = false;

//   constexpr bool automatic_flushes = false;
//   constexpr bool support_locking = false;
//   constexpr bool support_grcontext = false;

//   scoped_refptr<ui::ContextProviderCommandBuffer> context_provider(
//       new ui::ContextProviderCommandBuffer(
//           gpu_channel_host, GetGpuMemoryBufferManager(), common::kGpuStreamIdDefault,
//           common::kGpuStreamPriorityDefault, gpu::kNullSurfaceHandle, url,
//           automatic_flushes, support_locking, support_grcontext, limits,
//           attributes, ui::command_buffer_metrics::RENDER_COMPOSITOR_CONTEXT));

//   if (layout_test_deps_) {
//     if (!layout_test_deps_->UseDisplayCompositorPixelDump()) {
//       callback.Run(layout_test_deps_->CreateLayerTreeFrameSink(
//           routing_id, std::move(gpu_channel_host), std::move(context_provider),
//           std::move(worker_context_provider), GetGpuMemoryBufferManager(),
//           this));
//       return;
//     } else if (!params.compositor_task_runner) {
//       // The frame sink provider expects a compositor task runner, but we might
//       // not have that if we're running layout tests in single threaded mode.
//       // Set it to be our thread's task runner instead.
//       params.compositor_task_runner = GetCompositorMainThreadTaskRunner();
//     }
//   }

// // #if defined(OS_ANDROID)
// //   if (common::GetClient()->UsingSynchronousCompositing()) {
// //     RenderViewImpl* view = RenderViewImpl::FromRoutingID(routing_id);
// //     if (view) {
// //       callback.Run(std::make_unique<SynchronousLayerTreeFrameSink>(
// //           std::move(context_provider), std::move(worker_context_provider),
// //           compositor_task_runner_, GetGpuMemoryBufferManager(),
// //           sync_message_filter(), routing_id, g_next_layer_tree_frame_sink_id++,
// //           std::move(params.synthetic_begin_frame_source),
// //           view->widget_input_handler_manager()
// //               ->GetSynchronousCompositorRegistry(),
// //           std::move(frame_swap_message_queue)));
// //       return;
// //     } else {
// //       NOTREACHED();
// //     }
// //   }
// // #endif
//   frame_sink_provider_->CreateForWidget(
//       routing_id, std::move(compositor_frame_sink_request),
//       std::move(compositor_frame_sink_client),
//       std::move(render_frame_metadata_observer_client_request),
//       std::move(render_frame_metadata_observer_ptr));
//   params.gpu_memory_buffer_manager = GetGpuMemoryBufferManager();
//   callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
//       std::move(context_provider), std::move(worker_context_provider),
//       &params));
// }

void ApplicationThread::RequestNewLayerTreeFrameSink(
    int routing_id,
    scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue,
    const GURL& url,
    const LayerTreeFrameSinkCallback& callback,
    common::mojom::RenderFrameMetadataObserverClientRequest
        render_frame_metadata_observer_client_request,
    common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer_ptr) {
  
  // Misconfigured bots (eg. crbug.com/780757) could run layout tests on a
  // machine where gpu compositing doesn't work. Don't crash in that case.
  if (layout_test_mode() && is_gpu_compositing_disabled_) {
    LOG(FATAL) << "Layout tests require gpu compositing, but it is disabled.";
    return;
  }
  //const base::CommandLine& command_line =
  //    *base::CommandLine::ForCurrentProcess();
  //cc::mojo_embedder::AsyncLayerTreeFrameSink::InitParams params;
  viz::ClientLayerTreeFrameSink::InitParams params;
  DCHECK(compositor_task_runner_);
  params.compositor_task_runner = compositor_task_runner_;
  params.enable_surface_synchronization =
      features::IsSurfaceSynchronizationEnabled();
  params.local_surface_id_provider =
      std::make_unique<ApplicationLocalSurfaceIdProvider>();
  if (features::IsVizHitTestingDrawQuadEnabled()) {
    params.hit_test_data_provider =
        std::make_unique<viz::HitTestDataProviderDrawQuad>(
            true /* should_ask_for_child_region */);
  } else if (features::IsVizHitTestingSurfaceLayerEnabled()) {
    params.hit_test_data_provider =
      std::make_unique<viz::HitTestDataProviderSurfaceLayer>();
  }

  // The renderer runs animations and layout for animate_only BeginFrames.
  params.wants_animate_only_begin_frames = true;

  // In disable frame rate limit mode, also let the renderer tick as fast as it
  // can. The top level begin frame source will also be running as a back to
  // back begin frame source, but using a synthetic begin frame source here
  // reduces latency when in this mode (at least for frames starting--it
  // potentially increases it for input on the other hand.)
  //if (command_line.HasSwitch(switches::kDisableFrameRateLimit))
   //params.synthetic_begin_frame_source = CreateSyntheticBeginFrameSource();

  //if (command_line.HasSwitch(switches::kDisableGpuVsync) &&
  //  command_line.GetSwitchValueASCII(switches::kDisableGpuVsync) != "gpu") {
  //  params.synthetic_begin_frame_source = CreateSyntheticBeginFrameSource();
  //}

// #if defined(USE_AURA)
//   if (base::FeatureList::IsEnabled(features::kMash)) {
//     if (!RendererWindowTreeClient::Get(routing_id)) {
//       callback.Run(nullptr);
//       return;
//     }
//     scoped_refptr<gpu::GpuChannelHost> channel = EstablishGpuChannelSync();
//     // If the channel could not be established correctly, then return null. This
//     // would cause the compositor to wait and try again at a later time.
//     if (!channel) {
//       callback.Run(nullptr);
//       return;
//     }
//     RendererWindowTreeClient::Get(routing_id)
//         ->RequestLayerTreeFrameSink(
//             gpu_->CreateContextProvider(std::move(channel)),
//             GetGpuMemoryBufferManager(), callback);
//     frame_sink_provider_->RegisterRenderFrameMetadataObserver(
//         routing_id, std::move(render_frame_metadata_observer_client_request),
//         std::move(render_frame_metadata_observer_ptr));
//     return;
//   }
// #endif

  viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request =
      mojo::MakeRequest(&params.pipes.compositor_frame_sink_info);
  viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client;
  params.pipes.client_request =
      mojo::MakeRequest(&compositor_frame_sink_client);

  if (is_gpu_compositing_disabled_) {
    DLOG(ERROR) << "ApplicationThread::RequestNewLayerTreeFrameSink: BAD is_gpu_compositing_disabled_ = true";
    DCHECK(!layout_test_mode());
    frame_sink_provider_->CreateForWidget(
        routing_id, std::move(compositor_frame_sink_request),
        std::move(compositor_frame_sink_client));
    frame_sink_provider_->RegisterRenderFrameMetadataObserver(
        routing_id, std::move(render_frame_metadata_observer_client_request),
        std::move(render_frame_metadata_observer_ptr));
    //callback.Run(std::make_unique<cc::mojo_embedder::AsyncLayerTreeFrameSink>(
    //    nullptr, nullptr, &params));
    callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
        nullptr, nullptr, &params));
    return;
  }

  scoped_refptr<gpu::GpuChannelHost> gpu_channel_host =
      EstablishGpuChannelSync();
  if (!gpu_channel_host) {
    DLOG(ERROR) << "ApplicationThread::RequestNewLayerTreeFrameSink: BAD could not establish the channel with GPU";
    // Wait and try again. We may hear that the compositing mode has switched
    // to software in the meantime.
    callback.Run(nullptr);
    return;
  }

  scoped_refptr<viz::RasterContextProvider> worker_context_provider =
      SharedCompositorWorkerContextProvider();
  if (!worker_context_provider) {
    DLOG(ERROR) << "ApplicationThread::RequestNewLayerTreeFrameSink: BAD. creating viz::RasterContextProvider failed";
    
    // Cause the compositor to wait and try again.
    callback.Run(nullptr);
    return;
  }

  // The renderer compositor context doesn't do a lot of stuff, so we don't
  // expect it to need a lot of space for commands or transfer. Raster and
  // uploads happen on the worker context instead.
  gpu::SharedMemoryLimits limits = gpu::SharedMemoryLimits::ForMailboxContext();

  // This is for an offscreen context for the compositor. So the default
  // framebuffer doesn't need alpha, depth, stencil, antialiasing.
  

  gpu::ContextCreationAttribs attributes;
  attributes.alpha_size = -1;
  attributes.depth_size = 0;
  attributes.stencil_size = 0;
  attributes.samples = 0;
  attributes.sample_buffers = 0;
  attributes.bind_generates_resource = false;
  attributes.lose_context_when_out_of_memory = true;
  attributes.enable_gles2_interface = true;
  attributes.enable_raster_interface = false;
  attributes.enable_oop_rasterization = false;

  constexpr bool automatic_flushes = false;
  constexpr bool support_locking = false;
  constexpr bool support_grcontext = false;

  scoped_refptr<ui::ContextProviderCommandBuffer> context_provider(
      new ui::ContextProviderCommandBuffer(
          gpu_channel_host, GetGpuMemoryBufferManager(), common::kGpuStreamIdDefault,
          common::kGpuStreamPriorityDefault, gpu::kNullSurfaceHandle, url,
          automatic_flushes, support_locking, support_grcontext, limits,
          attributes, ui::command_buffer_metrics::RENDER_COMPOSITOR_CONTEXT));

  if (layout_test_deps_) {
    if (!layout_test_deps_->UseDisplayCompositorPixelDump()) {
      callback.Run(layout_test_deps_->CreateLayerTreeFrameSink(
          routing_id, std::move(gpu_channel_host), std::move(context_provider),
          std::move(worker_context_provider), GetGpuMemoryBufferManager(),
          this));
      return;
    } else if (!params.compositor_task_runner) {
      // The frame sink provider expects a compositor task runner, but we might
      // not have that if we're running layout tests in single threaded mode.
      // Set it to be our thread's task runner instead.
      params.compositor_task_runner = GetCompositorMainThreadTaskRunner();
    }
  }

// #if defined(OS_ANDROID)
//   if (GetContentClient()->UsingSynchronousCompositing()) {
//     RenderViewImpl* view = RenderViewImpl::FromRoutingID(routing_id);
//     if (view) {
//       callback.Run(std::make_unique<SynchronousLayerTreeFrameSink>(
//           std::move(context_provider), std::move(worker_context_provider),
//           compositor_task_runner_, GetGpuMemoryBufferManager(),
//           sync_message_filter(), routing_id, g_next_layer_tree_frame_sink_id++,
//           std::move(params.synthetic_begin_frame_source),
//           view->widget_input_handler_manager()
//               ->GetSynchronousCompositorRegistry(),
//           std::move(frame_swap_message_queue)));
//       return;
//     } else {
//       NOTREACHED();
//     }
//   }
// #endif
  frame_sink_provider_->CreateForWidget(
      routing_id, std::move(compositor_frame_sink_request),
      std::move(compositor_frame_sink_client));
  frame_sink_provider_->RegisterRenderFrameMetadataObserver(
      routing_id, std::move(render_frame_metadata_observer_client_request),
      std::move(render_frame_metadata_observer_ptr));
  params.gpu_memory_buffer_manager = GetGpuMemoryBufferManager();
  //callback.Run(std::make_unique<cc::mojo_embedder::AsyncLayerTreeFrameSink>(
  //    std::move(context_provider), std::move(worker_context_provider),
  //    &params));

  callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
       std::move(context_provider), std::move(worker_context_provider),
       &params));
}

void ApplicationThread::OnRequestNewLayerTreeFrameSink(
    void* state,
    void(*cb)(void*, void*),
    std::unique_ptr<cc::LayerTreeFrameSink> result) {  
  cc::LayerTreeFrameSink* ptr = nullptr;
  if (result) {
    ptr = result.release();
  }
  cb(state, ptr);
}

gpu::GpuMemoryBufferManager* ApplicationThread::GetGpuMemoryBufferManager() {
  DCHECK(gpu_->gpu_memory_buffer_manager());
  return gpu_->gpu_memory_buffer_manager();
}

std::unique_ptr<cc::SwapPromise> ApplicationThread::RequestCopyOfOutputForLayoutTest(
    int32_t routing_id,
    std::unique_ptr<viz::CopyOutputRequest> request) {
  DCHECK(layout_test_deps_ &&
         !layout_test_deps_->UseDisplayCompositorPixelDump());
  return layout_test_deps_->RequestCopyOfOutput(routing_id, std::move(request));
}

void ApplicationThread::OnMemoryStateChange(base::MemoryState state) {
  if (blink_platform_impl_) {
    blink::WebMemoryCoordinator::OnMemoryStateChange(
        static_cast<blink::MemoryState>(state));
  }
}

common::ServiceWorkerContextInstance* ApplicationThread::GetServiceWorkerContextInstance() {
  if (!service_worker_instance_) {
    void* worker_context_client_state = window_dispatcher_->GetServiceWorkerContextClientState(); 
    ServiceWorkerContextClientCallbacks callbacks = window_dispatcher_->GetServiceWorkerContextClientCallbacks();
    service_worker_instance_ = std::make_unique<common::ServiceWorkerContextInstance>(worker_context_client_state, std::move(callbacks));
  }
  return service_worker_instance_.get();
}

std::unique_ptr<common::WorkerNativeClientFactory> ApplicationThread::GetWorkerNativeClientFactory() {
  DCHECK(service_worker_instance_.get());
  return service_worker_instance_->CreateWorkerNativeClientFactory();
}

media::GpuVideoAcceleratorFactories* ApplicationThread::GetGpuFactories() {
  DCHECK(IsMainThread());

  if (!gpu_factories_.empty()) {
    if (!gpu_factories_.back()->CheckContextProviderLost())
      return gpu_factories_.back().get();

    GetMediaThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(base::IgnoreResult(
                           &GpuVideoAcceleratorFactoriesImpl::CheckContextLost),
                       base::Unretained(gpu_factories_.back().get())));
  }

  const base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();

  scoped_refptr<gpu::GpuChannelHost> gpu_channel_host =
      EstablishGpuChannelSync();
  if (!gpu_channel_host) {
    //DLOG(ERROR) << "ApplicationThread::GetGpuFactories: BAD. EstablishGpuChannelSync() failed";
    return nullptr;
  }
  // This context is only used to create textures and mailbox them, so
  // use lower limits than the default.
  gpu::SharedMemoryLimits limits = gpu::SharedMemoryLimits::ForMailboxContext();
  bool support_locking = false;
  bool support_gles2_interface = true;
  bool support_raster_interface = true;
  bool support_oop_rasterization = true;
  bool support_grcontext = false;
  scoped_refptr<ui::ContextProviderCommandBuffer> media_context_provider =
      CreateOffscreenContext(gpu_channel_host, GetGpuMemoryBufferManager(),
                             limits, support_locking, support_gles2_interface,
                             support_raster_interface,
                             support_oop_rasterization, support_grcontext,
                             ui::command_buffer_metrics::MEDIA_CONTEXT,
                             common::kGpuStreamIdMedia, common::kGpuStreamPriorityMedia);

  const bool enable_video_accelerator =
      !cmd_line->HasSwitch(switches::kDisableAcceleratedVideoDecode) &&
      (gpu_channel_host->gpu_feature_info()
           .status_values[gpu::GPU_FEATURE_TYPE_ACCELERATED_VIDEO_DECODE] ==
       gpu::kGpuFeatureStatusEnabled);
  const bool enable_gpu_memory_buffers =
      !is_gpu_compositing_disabled_; //&&
//#if defined(OS_MACOSX) || defined(OS_LINUX) || defined(OS_WIN)
//      !cmd_line->HasSwitch(switches::kDisableGpuMemoryBufferVideoFrames);
//#else
      //cmd_line->HasSwitch(switches::kEnableGpuMemoryBufferVideoFrames);
//#endif  // defined(OS_MACOSX) || defined(OS_LINUX) || defined(OS_WIN)
  const bool enable_media_stream_gpu_memory_buffers =
      enable_gpu_memory_buffers; //&&
      //base::FeatureList::IsEnabled(
          //features::kWebRtcUseGpuMemoryBufferVideoFrames);
  bool enable_video_gpu_memory_buffers = enable_gpu_memory_buffers;
#if defined(OS_WIN)
  enable_video_gpu_memory_buffers =
      enable_video_gpu_memory_buffers &&
      (cmd_line->HasSwitch(switches::kEnableGpuMemoryBufferVideoFrames) ||
       gpu_channel_host->gpu_info().supports_overlays);
#endif  // defined(OS_WIN)

  media::mojom::VideoEncodeAcceleratorProviderPtr vea_provider;
  gpu_->CreateVideoEncodeAcceleratorProvider(mojo::MakeRequest(&vea_provider));

  gpu_factories_.push_back(GpuVideoAcceleratorFactoriesImpl::Create(
      std::move(gpu_channel_host), base::ThreadTaskRunnerHandle::Get(),
      GetMediaThreadTaskRunner(), std::move(media_context_provider),
      enable_video_gpu_memory_buffers, enable_media_stream_gpu_memory_buffers,
      enable_video_accelerator, vea_provider.PassInterface()));
  gpu_factories_.back()->SetRenderingColorSpace(rendering_color_space_);
  return gpu_factories_.back().get();
}

scoped_refptr<base::SingleThreadTaskRunner> ApplicationThread::GetMediaThreadTaskRunner() {
  DCHECK(main_thread_runner()->BelongsToCurrentThread());
  if (!media_thread_) {
    media_thread_.reset(new base::Thread("Media"));
    media_thread_->Start();
  }
  return media_thread_->task_runner();
}

void ApplicationThread::OnPurgeMemory() {
 /* // Record amount of purged memory after 2 seconds. 2 seconds is arbitrary
  // but it works most cases.
  RendererMemoryMetrics metrics;
  if (!GetRendererMemoryMetrics(&metrics))
    return;

  GetWebMainThreadScheduler()->DefaultTaskRunner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RenderThreadImpl::RecordPurgeMemory,
                     base::Unretained(this), std::move(metrics)),
      base::TimeDelta::FromSeconds(2));

  OnTrimMemoryImmediately();
  ReleaseFreeMemory();
  if (blink_platform_impl_)
    blink::WebMemoryCoordinator::OnPurgeMemory();*/
}

void ApplicationThread::LoadResourceBundles() {
  // Init resource disk
 base::FilePath exe_path;
 base::GetCurrentDirectory(&exe_path);

 //DCHECK(r);
 base::FilePath blink_resources = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/public/resources/blink_resources.pak"));
 //if (!ui::ResourceBundle::HasSharedInstance()) {
   ui::ResourceBundle::InitSharedInstanceWithPakPath(blink_resources); 
 //} else {
 //  ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(blink_resources, ui::SCALE_FACTOR_100P);  
 //}
 
 base::FilePath blink_image_resources = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/public/resources/blink_image_resources_100_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(blink_image_resources, ui::SCALE_FACTOR_100P);

 base::FilePath blink_image_resources_200 = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/public/resources/blink_image_resources_200_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(blink_image_resources_200, ui::SCALE_FACTOR_200P);

 base::FilePath media_controls_resources_100 = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/renderer/modules/media_controls/resources/media_controls_resources_100_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(media_controls_resources_100, ui::SCALE_FACTOR_100P);

 base::FilePath media_controls_resources_200 = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/renderer/modules/media_controls/resources/media_controls_resources_200_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(media_controls_resources_200, ui::SCALE_FACTOR_200P);
}

bool ApplicationThread::IsMainThread() {
  return !!current();
}

blink::WebMediaPlayer* ApplicationThread::CreateWebMediaPlayer(
    void* delegate_state,
    WebMediaPlayerDelegateCallbacks callbacks, 
    blink::WebLocalFrame* web_frame,
    const blink::WebMediaPlayerSource& source,
    blink::WebMediaPlayerClient* client,
    blink::WebMediaPlayerEncryptedMediaClient* enc_client,
    blink::WebContentDecryptionModule* mod, 
    blink::WebString sink_id,
    blink::WebLayerTreeView* layer_tree_view,
    const cc::LayerTreeSettings& settings) {
  MediaFactory* factory = nullptr;
  for (auto it = media_factories_.begin(); it != media_factories_.end(); ++it) {
    blink::WebLocalFrame* cur_frame = it->first;
    if (cur_frame == web_frame) {
      factory = it->second.get();
      break;
    }
  }
  // not found -> create
  if (!factory) {
    std::unique_ptr<MediaFactory> media_factory(new MediaFactory(
      this, 
      web_frame,
      delegate_state,
      callbacks,
      base::Bind(&ApplicationThread::RequestOverlayRoutingToken,
                  base::Unretained(this))));
    factory = media_factory.get();
    // Must call after binding our own remote interfaces.
    media_factory->SetupMojo();
    media_factories_.push_back(std::make_pair(web_frame, std::move(media_factory)));
  }
  return factory->CreateMediaPlayer(web_frame,
                                    source, client, enc_client,
                                    mod, std::move(sink_id), layer_tree_view,
                                    settings);
}

void ApplicationThread::SetRenderingColorSpace(
    const gfx::ColorSpace& color_space) {
  DCHECK(IsMainThread());
  rendering_color_space_ = color_space;

  for (const auto& factories : gpu_factories_) {
    if (factories)
      factories->SetRenderingColorSpace(color_space);
  }
}

void ApplicationThread::WindowCreated() {
  bool renderer_was_hidden = RendererIsHidden();
  widget_count_++;
  if (renderer_was_hidden)
    OnRendererVisible();
}

void ApplicationThread::WindowHidden() {
  //DLOG(INFO) << "ApplicationThread::WindowHidden: " << hidden_widget_count_;
  DCHECK_LT(hidden_widget_count_, widget_count_);
  hidden_widget_count_++;
  if (RendererIsHidden())
    OnRendererHidden();
}

void ApplicationThread::WindowRestored() {
  //DLOG(INFO) << "ApplicationThread::WindowRestored: " << hidden_widget_count_;
  bool renderer_was_hidden = RendererIsHidden();
  DCHECK_GT(hidden_widget_count_, 0);
  hidden_widget_count_--;
  if (renderer_was_hidden)
    OnRendererVisible();
}

bool ApplicationThread::RendererIsHidden() const {
  //DLOG(INFO) << "ApplicationThread::RendererIsHidden: widget_count = " << widget_count_ << " hidden_widget_count = " << hidden_widget_count_;
  return widget_count_ > 0 && hidden_widget_count_ == widget_count_;
}

void ApplicationThread::OnRendererHidden() {
  blink::MainThreadIsolate()->IsolateInBackgroundNotification();
  // TODO(rmcilroy): Remove IdleHandler and replace it with an IdleTask
  // scheduled by the RendererScheduler - http://crbug.com/469210.
  //if (!GetContentClient()->renderer()->RunIdleHandlerWhenWidgetsHidden())
  //  return;
  main_thread_scheduler_->SetRendererHidden(true);
  ScheduleIdleHandler(kInitialIdleHandlerDelayMs);
}

void ApplicationThread::OnRendererVisible() {
  blink::MainThreadIsolate()->IsolateInForegroundNotification();
  main_thread_scheduler_->SetRendererHidden(false);
  ScheduleIdleHandler(kLongIdleHandlerDelayMs);
}

void ApplicationThread::RequestOverlayRoutingToken(
    media::RoutingTokenCallback callback) {
  if (overlay_routing_token_.has_value()) {
   std::move(callback).Run(overlay_routing_token_.value());
   return;
  }
  //Send a request to the host for the token.  We'll notify |callback| when it
  // web_arrives later.
  //Send(new FrameHostMsg_RequestOverlayRoutingToken(routing_id_));
  window_dispatcher()->SendRequestOverlayRoutingToken();
  pending_routing_token_callbacks_.push_back(std::move(callback));
}

void ApplicationThread::OnWebFrameCreated(blink::WebLocalFrame* frame, bool is_main) {
  //automation_context_->Init(binder_registry_, frame, GetIPCTaskRunner());
  automation_context_->OnWebFrameCreated(frame);
}

}
