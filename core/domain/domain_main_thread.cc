// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_main_thread.h"

#ifndef INSIDE_BLINK
#define INSIDE_BLINK 1
#endif

#include "base/allocator/allocator_extension.h"
#include "base/base_switches.h"
#include "base/macros.h"
#include "base/command_line.h"
#include "base/debug/leak_annotations.h"
#include "base/debug/alias.h"
#include "base/debug/profiler.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/message_loop/timer_slack.h"
#include "base/process/kill.h"
#include "base/process/process_handle.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/path_service.h"
#include "base/threading/thread_restrictions.h"
#include "base/memory/discardable_memory_allocator.h"
#include "base/memory/memory_coordinator_client_registry.h"
#include "base/memory/shared_memory.h"
#include "ipc/ipc_logging.h"
#include "ipc/ipc_sync_channel.h"
#include "ipc/ipc_sync_message_filter.h"
#include "ipc/ipc_channel_mojo.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/incoming_broker_client_invitation.h"
#include "mojo/edk/embedder/named_platform_channel_pair.h"
#include "mojo/edk/embedder/platform_channel_pair.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "mojo/edk/embedder/named_platform_handle_utils.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "mojo/public/cpp/system/buffer.h"
#include "mojo/public/cpp/system/platform_handle.h"
#include "core/shared/common/child_process.h"
#include "core/shared/common/simple_connection_filter.h"
#include "core/shared/common/child_process_messages.h"
#include "core/shared/common/paths.h"
#include "core/shared/common/client.h"
#include "core/shared/common/switches.h"
#include "components/tracing/child/child_trace_message_filter.h"
#include "gpu/config/gpu_switches.h"
#include "core/shared/common/mojo_channel_switches.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "core/shared/common/service_worker/worker_native_client_factory.h"
#include "core/shared/common/child_histogram_fetcher_impl.h"
#include "core/shared/common/gpu_stream_constants.h"
#include "core/shared/common/compositor_helper.h"
#include "core/domain/categorized_worker_pool.h"
#include "core/domain/frame_swap_message_queue.h"
#include "core/domain/domain_thread_impl.h"
#include "core/domain/domain_process.h"
#include "core/domain/layer_tree_view.h"
#include "core/domain/blink_platform_impl.h"
#include "core/domain/resource_dispatcher.h"
#include "core/shared/domain/storage/storage_dispatcher.h"
#include "core/shared/domain/route/route_dispatcher.h"
#include "core/shared/domain/repo/repo_dispatcher.h"
#include "core/shared/domain/store/app_store_dispatcher.h"
#include "core/domain/device/device_dispatcher.h"
#include "core/domain/application/application_manager_client.h"
#include "core/domain/application/window_manager_client.h"
#include "core/domain/fileapi/file_system_dispatcher.h"
#include "core/domain/appcache/appcache_dispatcher.h"
#include "core/domain/appcache/appcache_frontend_impl.h"
#include "core/domain/module/module_dispatcher.h"
#include "core/domain/module/module_loader.h"
#include "core/shared/domain/module/module_client.h"
#include "core/shared/domain/application/application_driver.h"
#include "core/shared/domain/service/service_dispatcher.h"
#include "core/domain/module/module.h"
#include "core/domain/service_worker/service_worker_message_filter.h"
#include "core/domain/service_worker/embedded_worker_instance_client_impl.h"
#include "core/domain/notifications/notification_dispatcher.h"
#include "core/domain/identity/identity_manager_client.h"
#include "core/domain/launcher/launcher_client.h"
#include "core/domain/domain_context.h"
#include "core/domain/thread_safe_sender.h"
#include "components/discardable_memory/client/client_discardable_shared_memory_manager.h"
#include "components/viz/common/features.h"
#include "components/viz/client/client_layer_tree_frame_sink.h"
#include "components/viz/client/hit_test_data_provider.h"
#include "components/viz/client/hit_test_data_provider_draw_quad.h"
#include "components/viz/client/hit_test_data_provider_surface_layer.h"
#include "components/viz/client/local_surface_id_provider.h"
#include "components/viz/common/frame_sinks/copy_output_request.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "cc/base/histograms.h"
#include "cc/base/switches.h"
#include "cc/blink/web_layer_impl.h"
#include "cc/raster/task_graph_runner.h"
#include "cc/trees/layer_tree_frame_sink.h"
#include "cc/trees/layer_tree_host_common.h"
#include "cc/trees/layer_tree_settings.h"
#include "rpc/grpc.h"
#include "services/ui/public/cpp/gpu/context_provider_command_buffer.h"
#include "services/ui/public/cpp/gpu/gpu.h"
#include "services/ui/public/interfaces/constants.mojom.h"
#include "services/service_manager/public/cpp/service_context.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/resource_coordinator/public/cpp/memory_instrumentation/client_process_impl.h"
#include "services/resource_coordinator/public/mojom/memory_instrumentation/memory_instrumentation.mojom.h"
#include "services/resource_coordinator/public/mojom/service_constants.mojom.h"
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
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/public/platform/web_private_ptr.h"
#include "core/domain/main_shadow_page.h"
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

namespace domain {

namespace {

base::LazyInstance<base::ThreadLocalPointer<DomainMainThread>>::DestructorAtExit g_lazy_tls =
 LAZY_INSTANCE_INITIALIZER;

base::LazyInstance<scoped_refptr<base::SingleThreadTaskRunner>>::
    DestructorAtExit g_main_task_runner = LAZY_INSTANCE_INITIALIZER;

const int64_t kLongIdleHandlerDelayMs = 30 * 1000;

// How long to wait for a connection to the browser process before giving up.
const int kConnectionTimeoutS = 15;

const char kV8SnapshotDataDescriptor[] = "v8_snapshot_data";

const size_t kImageCacheSingleAllocationByteLimit = 64 * 1024 * 1024;

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
      GURL("mumba://gpu/DomainMainThread::CreateOffscreenContext/" +
           ui::command_buffer_metrics::ContextTypeToString(type)),
      automatic_flushes, support_locking, support_grcontext, limits, attributes,
      type);
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
    if (source_info.identity.name() != common::mojom::kHostServiceName) {
      //DLOG(ERROR) << "calling binder '" << source_info.identity.name() << "' not host. not binding";
      return;
    }

    if (interface_name == IPC::mojom::ChannelBootstrap::Name_) {
      DCHECK(bootstrap_.is_valid());
      mojo::FuseInterface(
          IPC::mojom::ChannelBootstrapRequest(std::move(*interface_pipe)),
          std::move(bootstrap_));
    }
  }

  IPC::mojom::ChannelBootstrapPtrInfo bootstrap_;

  DISALLOW_COPY_AND_ASSIGN(ChannelBootstrapFilter);
};

class DomainLocalSurfaceIdProvider : public viz::LocalSurfaceIdProvider {
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

} // namespace

static void MaxObservedSizeFunction(size_t size_in_mb) {}

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

  gin::V8Initializer::LoadV8Snapshot(kSnapshotType);
}

void LoadV8NativesFile() {
  gin::V8Initializer::LoadV8Natives();
}

void InitializeV8IfNeeded() {
  LoadV8SnapshotFile();
  LoadV8NativesFile();
}

DomainMainThread::DomainMainThreadMessageRouter::DomainMainThreadMessageRouter(
    IPC::Sender* sender)
    : sender_(sender) {}

bool DomainMainThread::DomainMainThreadMessageRouter::Send(IPC::Message* msg) {
  return sender_->Send(msg);
}

bool DomainMainThread::DomainMainThreadMessageRouter::RouteMessage(
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

DomainMainThread::Options::Options()
    : auto_start_service_manager_connection(true), connect_to_browser(false) {}

DomainMainThread::Options::Options(const Options& other) = default;

DomainMainThread::Options::~Options() {
}

DomainMainThread::Options::Builder::Builder() {
}

DomainMainThread::Options::Builder&
DomainMainThread::Options::Builder::InBrowserProcess(
    const common::InProcessChildThreadParams& params) {
  options_.host_process_io_runner = params.io_runner();
  options_.in_process_service_request_token = params.service_request_token();
  options_.broker_client_invitation = params.broker_client_invitation();
  return *this;
}

DomainMainThread::Options::Builder&
DomainMainThread::Options::Builder::AutoStartServiceManagerConnection(
    bool auto_start) {
  options_.auto_start_service_manager_connection = auto_start;
  return *this;
}

DomainMainThread::Options::Builder&
DomainMainThread::Options::Builder::ConnectToBrowser(
    bool connect_to_browser_parms) {
  options_.connect_to_browser = connect_to_browser_parms;
  return *this;
}

DomainMainThread::Options::Builder&
DomainMainThread::Options::Builder::AddStartupFilter(
    IPC::MessageFilter* filter) {
  options_.startup_filters.push_back(filter);
  return *this;
}

DomainMainThread::Options::Builder&
DomainMainThread::Options::Builder::IPCTaskRunner(
    scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_parms) {
  options_.ipc_task_runner = ipc_task_runner_parms;
  return *this;
}

DomainMainThread::Options DomainMainThread::Options::Builder::Build() {
  return options_;
}

// static 
DomainMainThread* DomainMainThread::Create(
    std::unique_ptr<base::MessageLoop> message_loop,
    std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
    const base::CommandLine& cmd,
    const base::FilePath& domain_root,
    const base::UUID& domain_id,
    const std::string& domain_name,
    const std::string& bundle_path,
    int process_id) {
  return new DomainMainThread(
    std::move(message_loop), 
    std::move(scheduler), 
    cmd, 
    domain_root, 
    domain_id, 
    domain_name,
    bundle_path,
    process_id,
   Options::Builder()
              .ConnectToBrowser(true)
              .IPCTaskRunner(nullptr) 
              .Build());
}
 

// static 
DomainMainThread* DomainMainThread::current() {
  return g_lazy_tls.Pointer()->Get();
}	

DomainMainThread::DomainMainThread(
  std::unique_ptr<base::MessageLoop> message_loop,
  std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
  const base::CommandLine& cmd,
  const base::FilePath& domain_root,
  const base::UUID& domain_id,
  const std::string& domain_name,
  const std::string& bundle_path,
  int process_id,
  const Options& options):
  // common::ChildThreadImpl(
  //     Options::Builder()
  //             .AutoStartServiceManagerConnection(true)
  //             .ConnectToBrowser(true)
  //             .ManualInit(true)
  //             .IPCTaskRunner(nullptr) 
  //             .Build()),
  process_id_(process_id),
  routing_id_(process_id),
  bundle_path_(bundle_path),
  message_loop_(std::move(message_loop)),
  domain_binding_(this),
  domain_context_(new DomainContext(this, domain_root, domain_id, domain_name)),
  main_thread_scheduler_(std::move(scheduler)),
  route_provider_binding_(this),
  initialized_(false),
  categorized_worker_pool_(new CategorizedWorkerPool()),
  is_scroll_animator_enabled_(false),
  compositing_mode_watcher_binding_(this),
  compositor_helper_(std::make_unique<common::CompositorHelper>(this)),
  frame_swap_message_queue_(new FrameSwapMessageQueue(routing_id_)),
  ipc_task_runner_(options.ipc_task_runner),
  on_channel_error_called_(false),
  devtools_worker_token_(base::UnguessableToken::Create()),
  wait_on_blink_io_init_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
  router_(this),
  channel_connected_factory_(
          new base::WeakPtrFactory<DomainMainThread>(this)),
  weak_factory_(this) {
 
  g_lazy_tls.Pointer()->Set(this);

  common::ChildProcess* process = common::ChildProcess::current();
  //process->set_main_thread(this);

  main_task_runner_ = message_loop_->task_runner();
  io_task_runner_ = process->io_task_runner();

  //io_task_runner_->PostTask(
  //  FROM_HERE,
  //  base::BindOnce(
  //    &DomainMainThread::Init,
  //    base::Unretained(this),
  //    cmd, 
  //    main_task_runner_));
  Init(cmd,
   Options::Builder()
              .ConnectToBrowser(true)
              .IPCTaskRunner(nullptr) 
              .Build());
}

DomainMainThread::~DomainMainThread() {
  channel()->RemoveFilter(sync_message_filter_.get());
  g_main_task_runner.Get() = nullptr;
  domain_context_ = nullptr;
}

void DomainMainThread::Init(const base::CommandLine& cmd, const Options& options) {//, 
  //scoped_refptr<base::SingleThreadTaskRunner> main_task_runner) {
  base::ScopedAllowBlockingForTesting allow_blocking;
  base::ScopedAllowBaseSyncPrimitivesForTesting allow_sync;

  GetIOTaskRunner()->PostTask(FROM_HERE, base::BindOnce(&DomainMainThread::InitializeWebKitOnIOThread, base::Unretained(this)));
  wait_on_blink_io_init_.Wait();

  grpc_init();

  //ChildThreadImpl::Init();

  main_thread_.reset(new DomainThreadImpl(
      DomainThread::UI, main_task_runner_));

  g_main_task_runner.Get() = message_loop_->task_runner();

  //ApplicationProcess* process = common::ChildProcess::current();
  //process->set_main_thread(this);
  channel_ = IPC::SyncChannel::Create(
      this, common::ChildProcess::current()->io_task_runner(),
      ipc_task_runner_ ? ipc_task_runner_ : base::ThreadTaskRunnerHandle::Get(),
      common::ChildProcess::current()->GetShutDownEvent());
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
  
  sync_message_filter_ = channel()->CreateSyncMessageFilter();

  thread_safe_sender_ =
      new ThreadSafeSender(main_task_runner_, sync_message_filter_.get());

  resource_dispatcher_.reset(new ResourceDispatcher());

  InitializeV8IfNeeded();

  auto registry = std::make_unique<service_manager::BinderRegistry>();
  service_manager::BinderRegistry* registry_ref = registry.get();
  scoped_refptr<base::SingleThreadTaskRunner> resource_task_queue;

  InitializeWebKit(resource_task_queue, registry_ref);

  registry->AddInterface(base::Bind(&DomainMainThread::OnChildControlRequest,
                                    base::Unretained(this)),
                         base::ThreadTaskRunnerHandle::Get());

  RegisterMojoInterfaces();

  GetServiceManagerConnection()->AddConnectionFilter(
      std::make_unique<common::SimpleConnectionFilter>(std::move(registry)));    
  
  InitTracing();

  // In single process mode, browser-side tracing and memory will cover the
  // whole process including renderers.
  if (!IsInHostProcess()) {
    if (GetServiceManagerConnection()) {
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

  main_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&DomainMainThread::EnsureConnected,
                     channel_connected_factory_->GetWeakPtr()),
      base::TimeDelta::FromSeconds(connection_timeout));

#if defined(OS_ANDROID)
  g_quit_closure.Get().BindToMainThread();
#endif

  gpu_ = ui::Gpu::Create(GetConnector(),
                         base::FeatureList::IsEnabled(features::kMash)
                           ? ui::mojom::kServiceName
                           : common::mojom::kHostServiceName,
                         GetIOTaskRunner());

  appcache_dispatcher_.reset(
      new AppCacheDispatcher(new AppCacheFrontendImpl()));
      
  registry_ref->AddInterface(
      base::BindRepeating(&AppCacheDispatcher::Bind,
                          base::Unretained(appcache_dispatcher_.get())),
      GetMainTaskRunner());

  registry_ref->AddInterface(
      base::BindRepeating(&EmbeddedWorkerInstanceClientImpl::Create,
                          base::TimeTicks::Now(), GetIOTaskRunner()),
      GetMainTaskRunner());

  // bind storage host
  GetChannel()->GetRemoteAssociatedInterface(
    &domain_context_->storage_dispatcher()->storage_dispatcher_host_interface_);
  
  //DCHECK(domain_context_->storage_dispatcher()->storage_dispatcher_host_interface_);

  GetChannel()->GetRemoteAssociatedInterface(
    &domain_context_->application_manager_client()->application_manager_host_);
  //DCHECK(domain_context_->application_manager_client()->application_manager_host_);

  GetChannel()->GetRemoteAssociatedInterface(&domain_context_->domain_registry_interface_);
  //DCHECK(domain_context_->domain_registry_interface_);

  GetChannel()->GetRemoteAssociatedInterface(&domain_context_->service_registry_interface_);
  //DCHECK(domain_context_->service_registry_interface_);

  GetChannel()->GetRemoteAssociatedInterface(&domain_context_->channel_registry_interface_);
  //DCHECK(domain_context_->channel_registry_interface_);
  
  GetChannel()->GetRemoteAssociatedInterface(
    &domain_context_->route_dispatcher()->route_dispatcher_client_);

  GetChannel()->GetRemoteAssociatedInterface(
    &domain_context_->repo_dispatcher()->repo_dispatcher_);
  
  GetChannel()->GetRemoteAssociatedInterface(
    &domain_context_->app_store_dispatcher()->app_store_dispatcher_);

  LoadResourceBundles();

  WTF::String app_scheme = WTF::String::FromUTF8(domain_context_->name().c_str());
  blink::SchemeRegistry::RegisterURLSchemeAsSecure(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsCORSEnabled(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsAllowingServiceWorkers(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsSupportingFetchAPI(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeBypassingSecureContextCheck(app_scheme);
  blink::SchemeRegistry::RegisterURLSchemeAsAllowingWasmEvalCSP(app_scheme);
  
  common::ScreenInfo screen_info;
  
  screen_info.rect = gfx::Rect(800,600);
  screen_info.available_rect = gfx::Rect(800,600);
  
  main_shadow_page_ = std::make_unique<MainShadowPage>(this, std::move(screen_info), 1.0);
  main_shadow_page_->Initialize();

  if (!domain_context_->Init(p2p_socket_dispatcher_.get(), main_task_runner_, GetIOTaskRunner(), GetChannel(), GetAssociatedInterfaceRegistry())) {
    //DLOG(ERROR) << "failed initializing app host context";
    return;
  }

  initialized_ = true;
}

void DomainMainThread::InitTracing() {
  // In single process mode, browser-side tracing and memory will cover the
  // whole process including renderers.
  // if (IsInHostProcess())
  //   return;

  // // Tracing adds too much overhead to the profiling service. The only
  // // way to determine if this is the profiling service is by checking the
  // // sandbox type.
  // service_manager::SandboxType sandbox_type =
  //     service_manager::SandboxTypeFromCommandLine(
  //         *base::CommandLine::ForCurrentProcess());
  // if (sandbox_type == service_manager::SANDBOX_TYPE_PROFILING)
  //   return;

  // channel_->AddFilter(new tracing::ChildTraceMessageFilter(
  //     common::ChildProcess::current()->io_task_runner()));

  // trace_event_agent_ = tracing::TraceEventAgent::Create(
  //     GetConnector(), false /* request_clock_sync_marker_on_android */);

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

  //media::InitializeMediaLibrary();

  int num_raster_threads = 2;

// #if defined(OS_LINUX)
//   categorized_worker_pool_->SetBackgroundingCallback(
//       main_thread_scheduler_->DefaultTaskRunner(),
//       base::BindOnce(
//           [](base::WeakPtr<DomainMainThread> render_thread,
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
      std::move(manager_ptr), GetMainTaskRunner());//GetIOTaskRunner());

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

void DomainMainThread::RegisterMojoInterfaces() {
  service_worker_message_filter_ = new ServiceWorkerMessageFilter(
      thread_safe_sender(), GetMainTaskRunner());
  AddFilter(service_worker_message_filter_->GetFilter());

  p2p_socket_dispatcher_ = new P2PSocketDispatcher(GetIOTaskRunner().get());
  AddFilter(p2p_socket_dispatcher_.get());

  file_system_dispatcher_.reset(new FileSystemDispatcher());

  notification_dispatcher_ = new NotificationDispatcher(
      thread_safe_sender(), GetMainTaskRunner());//GetWebMainThreadScheduler()->IPCTaskRunner());
  AddFilter(notification_dispatcher_->GetFilter());

  GetAssociatedInterfaceRegistry()->AddInterface(
       base::BindRepeating(&DomainMainThread::OnDomainInterfaceRequest,
                  base::Unretained(this)));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&StorageDispatcher::Bind,
                          base::Unretained(domain_context()->storage_dispatcher())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&ModuleDispatcher::Bind,
                          base::Unretained(domain_context()->module_dispatcher())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&DeviceDispatcher::Bind,
                          base::Unretained(domain_context()->device_dispatcher())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&WindowManagerClient::Bind,
                          base::Unretained(domain_context()->window_manager_client())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&ServiceDispatcher::Bind,
                          base::Unretained(domain_context()->service_dispatcher())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&IdentityManagerClient::Bind,
                          base::Unretained(domain_context()->identity_manager_client())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&ApplicationManagerClient::Bind,
                          base::Unretained(domain_context()->application_manager_client())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&LauncherClient::Bind,
                          base::Unretained(domain_context()->launcher_client())));

  GetAssociatedInterfaceRegistry()->AddInterface(
      base::BindRepeating(&RouteDispatcher::Bind,
                          base::Unretained(domain_context()->route_dispatcher())));

  // GetAssociatedInterfaceRegistry()->AddInterface(
  //     base::BindRepeating(&RepoDispatcher::Bind,
  //                         base::Unretained(domain_context()->repo_dispatcher())));

  // GetAssociatedInterfaceRegistry()->AddInterface(
  //     base::BindRepeating(&AppStoreDispatcher::Bind,
  //                         base::Unretained(domain_context()->app_store_dispatcher())));
    
}

void DomainMainThread::InitializeWebKit(
    const scoped_refptr<base::SingleThreadTaskRunner>& resource_task_queue,
    service_manager::BinderRegistry* registry) {
  DCHECK(main_task_runner_->RunsTasksInCurrentSequence());

  DCHECK(!blink_platform_impl_);
  blink_platform_impl_.reset(
      new BlinkPlatformImpl(this, main_thread_scheduler_.get(), main_task_runner_, io_task_runner_));
  blink::Initialize(blink_platform_impl_.get(), registry);

  main_thread_compositor_task_runner_ =
      main_thread_scheduler_->CompositorTaskRunner();
  
  InitializeCompositorThread();
  
  DCHECK(GetWebMainThreadScheduler());
  idle_timer_.SetTaskRunner(GetWebMainThreadScheduler()->DefaultTaskRunner());
  ScheduleIdleHandler(kLongIdleHandlerDelayMs);
  main_thread_scheduler_->SetFreezingWhenBackgroundedEnabled(false);
  SkGraphics::SetResourceCacheSingleAllocationByteLimit(
      kImageCacheSingleAllocationByteLimit);
  SkGraphics::SetImageGeneratorFromEncodedDataFactory(
      blink::WebImageGenerator::CreateAsSkImageGenerator);
}

void DomainMainThread::InitializeWebKitOnIOThread() {
  WTF::Partitions::Initialize(MaxObservedSizeFunction);
  wait_on_blink_io_init_.Signal();
}

scoped_refptr<base::SingleThreadTaskRunner> DomainMainThread::GetIPCTaskRunner() {
  return message_loop()->task_runner();
}

void DomainMainThread::Shutdown() {
  domain_context_->Shutdown();
 // if (initialized_ && channel_) {
 //  channel_->ClearIPCTaskRunner();
 // }
 // channel_.reset();
  OnProcessFinalRelease();
  grpc_shutdown();
  g_lazy_tls.Pointer()->Set(nullptr);
  initialized_ = false;
}

void DomainMainThread::InitializeCompositorThread() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  base::ScopedAllowBaseSyncPrimitivesForTesting allow_sync;
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
}

void DomainMainThread::SetResourceDispatcherDelegate(
    ResourceDispatcherDelegate* delegate) {
  resource_dispatcher_->set_delegate(delegate);
}

common::mojom::StorageDispatcherHost* DomainMainThread::GetStorageDispatcherHost() {
  return domain_context_->storage_dispatcher()->GetStorageDispatcherHostInterface();
}

void DomainMainThread::OnChannelConnected(int32_t peer_pid) {
  channel_connected_factory_.reset();
}

void DomainMainThread::OnChannelError() {
  on_channel_error_called_ = true;
  // If this thread runs in the browser process, only Thread::Stop should
  // stop its message loop. Otherwise, QuitWhenIdle could race Thread::Stop.
  if (!IsInHostProcess())
    base::RunLoop::QuitCurrentWhenIdleDeprecated();
}

void DomainMainThread::OnAssociatedInterfaceRequest(
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
    } 
    // else {
    //   LOG(ERROR) << "Request for unknown Channel-associated interface: "
    //              << name;
    // }
  }
}

scoped_refptr<base::SingleThreadTaskRunner> DomainMainThread::GetIOTaskRunner() {
  if (IsInHostProcess())
    return host_process_io_runner_;
  return common::ChildProcess::current()->io_task_runner();
}

scoped_refptr<base::SingleThreadTaskRunner> DomainMainThread::GetMainTaskRunner() {
  return main_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner> DomainMainThread::DeprecatedGetMainTaskRunner() {
  return g_main_task_runner.Get();
}

IPC::SyncChannel* DomainMainThread::GetChannel() {
  return channel();
}

IPC::SyncMessageFilter* DomainMainThread::GetSyncMessageFilter() {
  return sync_message_filter();
}

void DomainMainThread::AddRoute(int32_t routing_id, IPC::Listener* listener) {
  GetRouter()->AddRoute(routing_id, listener);
}
 
void DomainMainThread::RemoveRoute(int32_t routing_id) {
  GetRouter()->RemoveRoute(routing_id);
}

common::mojom::DomainHost* DomainMainThread::GetDomainHost() {
  if (!domain_host_) {
    GetChannel()->GetRemoteAssociatedInterface(&domain_host_);
  }
  return domain_host_.get();
}
 
int DomainMainThread::GenerateRoutingID() {
  int32_t routing_id = MSG_ROUTING_NONE;
  domain_message_filter()->GenerateRoutingID(&routing_id);
  return routing_id;
}

bool DomainMainThread::Send(IPC::Message* msg) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  if (!channel_) {
    delete msg;
    return false;
  }

  return channel_->Send(msg);
}

void DomainMainThread::AddFilter(IPC::MessageFilter* filter) {
  channel()->AddFilter(filter);
}
 
void DomainMainThread::RemoveFilter(IPC::MessageFilter* filter) {
 channel()->RemoveFilter(filter);
}

common::ServiceManagerConnection* DomainMainThread::GetServiceManagerConnection() {
  return service_manager_connection_.get();
}

common::mojom::DomainMessageFilter* DomainMainThread::domain_message_filter() {
  if (!domain_message_filter_)
    GetChannel()->GetRemoteAssociatedInterface(&domain_message_filter_);

  return domain_message_filter_.get();
}

std::unique_ptr<common::WorkerNativeClientFactory> DomainMainThread::GetWorkerNativeClientFactory() {
  DCHECK(service_worker_instance_.get());
  return service_worker_instance_->CreateWorkerNativeClientFactory();
}

common::ServiceWorkerContextInstance* DomainMainThread::GetServiceWorkerContextInstance() {
  if (!service_worker_instance_) {
    DCHECK(domain_context_->module_loader()->active_module());
    ModuleClient* module_client = domain_context_->module_loader()->active_module()->module_client();
    void* worker_context_client_state = module_client->GetServiceWorkerContextClientState();
    ServiceWorkerContextClientCallbacks callbacks = module_client->GetServiceWorkerContextClientCallbacks();
    service_worker_instance_ = std::make_unique<common::ServiceWorkerContextInstance>(worker_context_client_state, std::move(callbacks));
  }
  return service_worker_instance_.get();
}
 
void DomainMainThread::OnProcessFinalRelease() {
 if (on_channel_error_called())
  return;
  // The child process shutdown sequence is a request response based mechanism,
  // where we send out an initial feeler request to the child process host
  // instance in the browser to verify if it's ok to shutdown the child process.
  // The browser then sends back a response if it's ok to shutdown. This avoids
  // race conditions if the process refcount is 0 but there's an IPC message
  // inflight that would addref it.
 GetDomainHost()->ShutdownRequest();
}

bool DomainMainThread::OnControlMessageReceived(const IPC::Message& msg) {
 return false;
}

bool DomainMainThread::OnMessageReceived(const IPC::Message& msg) {
  if (file_system_dispatcher_->OnMessageReceived(msg)) {
    return true;
  }
  if (msg.routing_id() == MSG_ROUTING_CONTROL)
    return OnControlMessageReceived(msg);

  return router_.OnMessageReceived(msg);
}

void DomainMainThread::CreateEmbedderDomainService(
    service_manager::mojom::ServiceRequest service_request) {
 service_context_ = std::make_unique<service_manager::ServiceContext>(
      std::make_unique<service_manager::ForwardingService>(this),
      std::move(service_request));
}

void DomainMainThread::GetHandle(GetHandleCallback callback) {
  //DLOG(INFO) << "DomainMainThread::GetInfo";
}

service_manager::Connector* DomainMainThread::GetConnector() {
  return service_manager_connection_->GetConnector();
}

void DomainMainThread::OnStart() {
  context()->connector()->BindConnectorRequest(std::move(connector_request_));
}

void DomainMainThread::OnBindInterface(
    const service_manager::BindSourceInfo& remote_info,
    const std::string& name,
    mojo::ScopedMessagePipeHandle handle) {
  registry_.TryBindInterface(name, &handle);
}

void DomainMainThread::BindLocalInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  GetInterface(interface_name, std::move(interface_pipe));
}

common::mojom::RouteRegistry* DomainMainThread::GetRouteRegistry() {
  return domain_context_->GetRouteRegistry();
}

service_manager::InterfaceProvider* DomainMainThread::GetRemoteInterfaces() {
  return &remote_interfaces_;
}

common::mojom::RouteProvider* DomainMainThread::GetRemoteRouteProvider() {
  if (!remote_route_provider_) {
    DCHECK(channel_);
    channel_->GetRemoteAssociatedInterface(&remote_route_provider_);
  }
  return remote_route_provider_.get();
}

blink::AssociatedInterfaceRegistry*
DomainMainThread::GetAssociatedInterfaceRegistry() {
  return &associated_interfaces_;
}

blink::AssociatedInterfaceProvider*
DomainMainThread::GetRemoteAssociatedInterfaces() {
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

// void DomainMainThread::GetInterface(
//     const std::string& interface_name,
//     mojo::ScopedMessagePipeHandle interface_pipe) {
//   if (registry_.TryBindInterface(interface_name, &interface_pipe))
//     return;

//   // for (auto& observer : observers_) {
//   //   observer.OnInterfaceRequestForFrame(interface_name, &interface_pipe);
//   //   if (!interface_pipe.is_valid())
//   //     return;
//   // }
// }

void DomainMainThread::GetInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  connector_->BindInterface(
      service_manager::Identity(common::mojom::kDomainServiceName), interface_name,
      std::move(interface_pipe));
}

void DomainMainThread::OnDomainInterfaceRequest(
    common::mojom::DomainAssociatedRequest request) {
  DCHECK(!domain_binding_.is_bound());
  domain_binding_.Bind(std::move(request));
}

void DomainMainThread::ScheduleIdleHandler(int64_t initial_delay_ms) {
  idle_notification_delay_in_ms_ = initial_delay_ms;
  idle_timer_.Stop();
  idle_timer_.Start(FROM_HERE,
      base::TimeDelta::FromMilliseconds(initial_delay_ms),
      this, &DomainMainThread::IdleHandler);
}

void DomainMainThread::IdleHandler() {
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

void DomainMainThread::ReleaseFreeMemory() {
  base::allocator::ReleaseFreeMemory();
  discardable_shared_memory_manager_->ReleaseFreeMemory();

  // Do not call into blink if it is not initialized.
  if (blink_platform_impl_) {
    // Purge Skia font cache, resource cache, and image filter.
    SkGraphics::PurgeAllCaches();
    blink::DecommitFreeableMemory();
  }
}

std::unique_ptr<base::SharedMemory> DomainMainThread::HostAllocateSharedMemoryBuffer(size_t size) {
  return DomainMainThread::AllocateSharedMemory(size);
}

// static
std::unique_ptr<base::SharedMemory> DomainMainThread::AllocateSharedMemory(
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

void DomainMainThread::LoadResourceBundles() {
  // Init resource disk
 base::FilePath exe_path;
 base::GetCurrentDirectory(&exe_path);

 //DCHECK(r);
base::FilePath blink_resources = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/public/resources/blink_resources.pak"));
 if (!ui::ResourceBundle::HasSharedInstance()) {
   ui::ResourceBundle::InitSharedInstanceWithPakPath(blink_resources); 
 } else {
   ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(blink_resources, ui::SCALE_FACTOR_100P);  
 }
 
 base::FilePath blink_image_resources = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/public/resources/blink_image_resources_100_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(blink_image_resources, ui::SCALE_FACTOR_100P);

 base::FilePath blink_image_resources_200 = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/public/resources/blink_image_resources_200_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(blink_image_resources_200, ui::SCALE_FACTOR_200P);

 base::FilePath media_controls_resources_100 = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/renderer/modules/media_controls/resources/media_controls_resources_100_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(media_controls_resources_100, ui::SCALE_FACTOR_100P);

 base::FilePath media_controls_resources_200 = exe_path.Append(FILE_PATH_LITERAL("gen/third_party/blink/renderer/modules/media_controls/resources/media_controls_resources_200_percent.pak"));
 ui::ResourceBundle::GetSharedInstance().AddDataPackFromPath(media_controls_resources_200, ui::SCALE_FACTOR_200P);
}

// media::GpuVideoAcceleratorFactories* DomainMainThread::GetGpuFactories() {
//   DCHECK(IsMainThread());

//   if (!gpu_factories_.empty()) {
//     if (!gpu_factories_.back()->CheckContextProviderLost())
//       return gpu_factories_.back().get();

//     GetMediaThreadTaskRunner()->PostTask(
//         FROM_HERE,
//         base::BindOnce(base::IgnoreResult(
//                            &GpuVideoAcceleratorFactoriesImpl::CheckContextLost),
//                        base::Unretained(gpu_factories_.back().get())));
//   }

//   const base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();

//   scoped_refptr<gpu::GpuChannelHost> gpu_channel_host =
//       EstablishGpuChannelSync();
//   if (!gpu_channel_host) {
//     //DLOG(ERROR) << "DomainMainThread::GetGpuFactories: BAD. EstablishGpuChannelSync() failed";
//     return nullptr;
//   }
//   // This context is only used to create textures and mailbox them, so
//   // use lower limits than the default.
//   gpu::SharedMemoryLimits limits = gpu::SharedMemoryLimits::ForMailboxContext();
//   bool support_locking = false;
//   bool support_gles2_interface = true;
//   bool support_raster_interface = true;
//   bool support_oop_rasterization = true;
//   bool support_grcontext = false;
//   scoped_refptr<ui::ContextProviderCommandBuffer> media_context_provider =
//       CreateOffscreenContext(gpu_channel_host, GetGpuMemoryBufferManager(),
//                              limits, support_locking, support_gles2_interface,
//                              support_raster_interface,
//                              support_oop_rasterization, support_grcontext,
//                              ui::command_buffer_metrics::MEDIA_CONTEXT,
//                              common::kGpuStreamIdMedia, common::kGpuStreamPriorityMedia);

//   const bool enable_video_accelerator =
//       !cmd_line->HasSwitch(switches::kDisableAcceleratedVideoDecode) &&
//       (gpu_channel_host->gpu_feature_info()
//            .status_values[gpu::GPU_FEATURE_TYPE_ACCELERATED_VIDEO_DECODE] ==
//        gpu::kGpuFeatureStatusEnabled);
//   const bool enable_gpu_memory_buffers =
//       !is_gpu_compositing_disabled_; //&&
// //#if defined(OS_MACOSX) || defined(OS_LINUX) || defined(OS_WIN)
// //      !cmd_line->HasSwitch(switches::kDisableGpuMemoryBufferVideoFrames);
// //#else
//       //cmd_line->HasSwitch(switches::kEnableGpuMemoryBufferVideoFrames);
// //#endif  // defined(OS_MACOSX) || defined(OS_LINUX) || defined(OS_WIN)
//   const bool enable_media_stream_gpu_memory_buffers =
//       enable_gpu_memory_buffers; //&&
//       //base::FeatureList::IsEnabled(
//           //features::kWebRtcUseGpuMemoryBufferVideoFrames);
//   bool enable_video_gpu_memory_buffers = enable_gpu_memory_buffers;
// #if defined(OS_WIN)
//   enable_video_gpu_memory_buffers =
//       enable_video_gpu_memory_buffers &&
//       (cmd_line->HasSwitch(switches::kEnableGpuMemoryBufferVideoFrames) ||
//        gpu_channel_host->gpu_info().supports_overlays);
// #endif  // defined(OS_WIN)

//   media::mojom::VideoEncodeAcceleratorProviderPtr vea_provider;
//   gpu_->CreateVideoEncodeAcceleratorProvider(mojo::MakeRequest(&vea_provider));

//   gpu_factories_.push_back(GpuVideoAcceleratorFactoriesImpl::Create(
//       std::move(gpu_channel_host), base::ThreadTaskRunnerHandle::Get(),
//       GetMediaThreadTaskRunner(), std::move(media_context_provider),
//       enable_video_gpu_memory_buffers, enable_media_stream_gpu_memory_buffers,
//       enable_video_accelerator, vea_provider.PassInterface()));
//   gpu_factories_.back()->SetRenderingColorSpace(rendering_color_space_);
//   return gpu_factories_.back().get();
// }

void DomainMainThread::SetRenderingColorSpace(
    const gfx::ColorSpace& color_space) {
  DCHECK(IsMainThread());
  rendering_color_space_ = color_space;

  // for (const auto& factories : gpu_factories_) {
  //   if (factories)
  //     factories->SetRenderingColorSpace(color_space);
  // }
}

gpu::GpuMemoryBufferManager* DomainMainThread::GetGpuMemoryBufferManager() {
  DCHECK(gpu_->gpu_memory_buffer_manager());
  return gpu_->gpu_memory_buffer_manager();
}

std::unique_ptr<cc::SwapPromise> DomainMainThread::RequestCopyOfOutputForLayoutTest(
    std::unique_ptr<viz::CopyOutputRequest> request) {
  DCHECK(layout_test_deps_ &&
         !layout_test_deps_->UseDisplayCompositorPixelDump());
  return layout_test_deps_->RequestCopyOfOutput(routing_id_, std::move(request));
}

void DomainMainThread::OnMemoryStateChange(base::MemoryState state) {
  if (blink_platform_impl_) {
    blink::WebMemoryCoordinator::OnMemoryStateChange(
        static_cast<blink::MemoryState>(state));
  }
}

// void DomainMainThread::RequestNewLayerTreeFrameSink(
//     int routing_id,
//     scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue,
//     const GURL& url,
//     const LayerTreeFrameSinkCallback& callback,
//     common::mojom::RenderFrameMetadataObserverClientRequest
//         render_frame_metadata_observer_client_request,
//     common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer_ptr) {
  
//   // Misconfigured bots (eg. crbug.com/780757) could run layout tests on a
//   // machine where gpu compositing doesn't work. Don't crash in that case.
//   if (layout_test_mode() && is_gpu_compositing_disabled_) {
//     LOG(FATAL) << "Layout tests require gpu compositing, but it is disabled.";
//     return;
//   }
  
//   viz::ClientLayerTreeFrameSink::InitParams params;
//   DCHECK(compositor_task_runner_);
//   params.compositor_task_runner = compositor_task_runner_;
//   params.enable_surface_synchronization =
//       features::IsSurfaceSynchronizationEnabled();
//   params.local_surface_id_provider =
//       std::make_unique<DomainLocalSurfaceIdProvider>();
//   if (features::IsVizHitTestingDrawQuadEnabled()) {
//     params.hit_test_data_provider =
//         std::make_unique<viz::HitTestDataProviderDrawQuad>(
//             true /* should_ask_for_child_region */);
//   } else if (features::IsVizHitTestingSurfaceLayerEnabled()) {
//     params.hit_test_data_provider =
//       std::make_unique<viz::HitTestDataProviderSurfaceLayer>();
//   }

//   // The renderer runs animations and layout for animate_only BeginFrames.
//   params.wants_animate_only_begin_frames = true;

//   viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request =
//       mojo::MakeRequest(&params.pipes.compositor_frame_sink_info);
//   viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client;
//   params.pipes.client_request =
//       mojo::MakeRequest(&compositor_frame_sink_client);

//   if (is_gpu_compositing_disabled_) {
//     //DLOG(ERROR) << "DomainMainThread::RequestNewLayerTreeFrameSink: BAD is_gpu_compositing_disabled_ = true";
//     DCHECK(!layout_test_mode());
//     frame_sink_provider_->CreateForWidget(
//         routing_id, std::move(compositor_frame_sink_request),
//         std::move(compositor_frame_sink_client));
//     frame_sink_provider_->RegisterRenderFrameMetadataObserver(
//         routing_id, std::move(render_frame_metadata_observer_client_request),
//         std::move(render_frame_metadata_observer_ptr));
//     //callback.Run(std::make_unique<cc::mojo_embedder::AsyncLayerTreeFrameSink>(
//     //    nullptr, nullptr, &params));
//     callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
//         nullptr, nullptr, &params));
//     return;
//   }

//   scoped_refptr<gpu::GpuChannelHost> gpu_channel_host =
//       EstablishGpuChannelSync();
//   if (!gpu_channel_host) {
//     //DLOG(ERROR) << "DomainMainThread::RequestNewLayerTreeFrameSink: BAD could not establish the channel with GPU";
//     // Wait and try again. We may hear that the compositing mode has switched
//     // to software in the meantime.
//     callback.Run(nullptr);
//     return;
//   }

//   scoped_refptr<viz::RasterContextProvider> worker_context_provider =
//       SharedCompositorWorkerContextProvider();
//   if (!worker_context_provider) {
//     //DLOG(ERROR) << "DomainMainThread::RequestNewLayerTreeFrameSink: BAD. creating viz::RasterContextProvider failed";
    
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


//   frame_sink_provider_->CreateForWidget(
//       routing_id, std::move(compositor_frame_sink_request),
//       std::move(compositor_frame_sink_client));
//   frame_sink_provider_->RegisterRenderFrameMetadataObserver(
//       routing_id, std::move(render_frame_metadata_observer_client_request),
//       std::move(render_frame_metadata_observer_ptr));
//   params.gpu_memory_buffer_manager = GetGpuMemoryBufferManager();

//   callback.Run(std::make_unique<viz::ClientLayerTreeFrameSink>(
//        std::move(context_provider), std::move(worker_context_provider),
//        &params));
// }

scoped_refptr<gpu::GpuChannelHost> DomainMainThread::EstablishGpuChannelSync() {
  TRACE_EVENT0("gpu", "RenderThreadImpl::EstablishGpuChannelSync");
  scoped_refptr<gpu::GpuChannelHost> gpu_channel =
      gpu_->EstablishGpuChannelSync();
  if (gpu_channel)
    common::GetClient()->SetGpuInfo(gpu_channel->gpu_info());
  return gpu_channel;
}

scoped_refptr<viz::RasterContextProvider> DomainMainThread::SharedCompositorWorkerContextProvider() {
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

gpu::GpuChannelHost* DomainMainThread::GetGpuChannel() {
  return gpu_->GetGpuChannel().get();
}

cc::TaskGraphRunner* DomainMainThread::GetTaskGraphRunner() {
  DCHECK(categorized_worker_pool_->GetTaskGraphRunner());
  return categorized_worker_pool_->GetTaskGraphRunner();
}

scoped_refptr<ui::ContextProviderCommandBuffer> DomainMainThread::SharedMainThreadContextProvider() {
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

viz::SharedBitmapManager* DomainMainThread::GetSharedBitmapManager()  {
  // Assert compositor shims from sdk never call this when using application thread
  // as compositor dependencies 
  // (aka remote renderer/ not single-threaded compositor)
  DCHECK(false);
  return nullptr;
}

gpu::ImageFactory* DomainMainThread::GetImageFactory() {
 // Assert compositor shims from sdk never call this when using application thread
 // as compositor dependencies 
 // (aka remote renderer/ not single-threaded compositor) 
 DCHECK(false);
 return nullptr;
}

bool DomainMainThread::IsGpuRasterizationForced() {
  return is_gpu_rasterization_forced_;
}

int DomainMainThread::GetGpuRasterizationMSAASampleCount() {
  return gpu_rasterization_msaa_sample_count_;
}

bool DomainMainThread::IsLcdTextEnabled() {
  return is_lcd_text_enabled_;
}

bool DomainMainThread::IsZeroCopyEnabled() {
  return is_zero_copy_enabled_;
}

bool DomainMainThread::IsPartialRasterEnabled() {
  return is_partial_raster_enabled_;
}

bool DomainMainThread::IsGpuMemoryBufferCompositorResourcesEnabled() {
  return is_gpu_memory_buffer_compositor_resources_enabled_;
}

bool DomainMainThread::IsElasticOverscrollEnabled() {
  return is_elastic_overscroll_enabled_;
}

scoped_refptr<base::SingleThreadTaskRunner> DomainMainThread::GetCompositorMainThreadTaskRunner() {
  DCHECK(main_thread_compositor_task_runner_);
  return main_thread_compositor_task_runner_;  
}

scoped_refptr<base::SingleThreadTaskRunner> DomainMainThread::GetCompositorImplThreadTaskRunner() {
  DCHECK(compositor_task_runner_);
  return compositor_task_runner_;
}

blink::scheduler::WebMainThreadScheduler* DomainMainThread::GetWebMainThreadScheduler() {
  DCHECK(main_thread_scheduler_);
  return main_thread_scheduler_.get();
}

void DomainMainThread::CompositingModeFallbackToSoftware() {
  gpu_->LoseChannel();
  is_gpu_compositing_disabled_ = true;
}

bool DomainMainThread::IsThreadedAnimationEnabled() {
  return is_threaded_animation_enabled_;
}

bool DomainMainThread::IsScrollAnimatorEnabled() {
  return is_scroll_animator_enabled_;
}

std::unique_ptr<cc::UkmRecorderFactory> DomainMainThread::CreateUkmRecorderFactory() {
  return std::make_unique<UkmRecorderFactoryImpl>(GetConnector()->Clone());
}

common::CompositorHelper* DomainMainThread::compositor_helper() {
  return compositor_helper_.get();
}

void DomainMainThread::OnPurgeMemory() {}

void DomainMainThread::OnMainShadowPageInitialized() {

}

std::unique_ptr<blink::WebApplicationCacheHost> DomainMainThread::CreateApplicationCacheHost(blink::WebApplicationCacheHostClient*) {
  return std::unique_ptr<blink::WebApplicationCacheHost>();
}

const base::UnguessableToken& DomainMainThread::GetDevToolsWorkerToken() {
  return devtools_worker_token_;
}

void DomainMainThread::EnsureConnected() {
  VLOG(0) << "DomainMainThread::EnsureConnected()";
  base::Process::TerminateCurrentProcessImmediately(0);
}

void DomainMainThread::ConnectChannel(
    mojo::edk::IncomingBrokerClientInvitation* invitation) {
  DCHECK(service_manager_connection_);
  IPC::mojom::ChannelBootstrapPtr bootstrap;
  mojo::ScopedMessagePipeHandle handle =
      mojo::MakeRequest(&bootstrap).PassMessagePipe();
  service_manager_connection_->AddConnectionFilter(
      std::make_unique<ChannelBootstrapFilter>(bootstrap.PassInterface()));

  channel_->Init(
      IPC::ChannelMojo::CreateClientFactory(
          std::move(handle), common::ChildProcess::current()->io_task_runner(),
          ipc_task_runner_ ? ipc_task_runner_
                           : base::ThreadTaskRunnerHandle::Get()),
      true /* create_pipe_now */);
}

void DomainMainThread::StartServiceManagerConnection() {
  DCHECK(service_manager_connection_);
  service_manager_connection_->Start();
  common::GetClient()->OnServiceManagerConnected(
      service_manager_connection_.get());
}

void DomainMainThread::GetRoute(
    int32_t routing_id,
    common::mojom::AssociatedInterfaceProviderAssociatedRequest request) {
  associated_interface_provider_bindings_.AddBinding(
      this, std::move(request), routing_id);
}

void DomainMainThread::GetAssociatedInterface(
    const std::string& name,
    common::mojom::AssociatedInterfaceAssociatedRequest request) {
  int32_t routing_id =
      associated_interface_provider_bindings_.dispatch_context();
  Listener* route = router_.GetRoute(routing_id);
  if (route)
    route->OnAssociatedInterfaceRequest(name, request.PassHandle());
}

#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
void DomainMainThread::SetIPCLoggingEnabled(bool enable) {
  if (enable)
    IPC::Logging::GetInstance()->Enable();
  else
    IPC::Logging::GetInstance()->Disable();
}
#endif  //  IPC_MESSAGE_LOG_ENABLED

void DomainMainThread::ProcessShutdown() {
  base::RunLoop::QuitCurrentWhenIdleDeprecated();
}

bool DomainMainThread::IsInHostProcess() const {
  return static_cast<bool>(host_process_io_runner_);
}

// std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation> DomainMainThread::InitializeMojoIPCChannel() {
//   TRACE_EVENT0("startup", "InitializeMojoIPCChannel");
//   const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
//   std::string channel_name = "/tmp/";
//   channel_name.append(command_line.GetSwitchValueASCII("uuid"));
//   mojo::edk::NamedPlatformHandle named_handle(channel_name);
//   mojo::ScopedPlatformHandle platform_channel =
//   mojo::edk::CreateClientHandle(named_handle);
//   if (!platform_channel.is_valid())
//     return nullptr;

//   std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation> invitation =
//    mojo::edk::IncomingBrokerClientInvitation::Accept(
//       mojo::edk::ConnectionParams(mojo::edk::TransportProtocol::kLegacy,
//                                   std::move(platform_channel)));
//   return invitation;
// }

std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation>
DomainMainThread::InitializeMojoIPCChannel() {
  TRACE_EVENT0("startup", "InitializeMojoIPCChannel");
  mojo::ScopedPlatformHandle platform_channel;
#if defined(OS_WIN)
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
      mojo::edk::PlatformChannelPair::kMojoPlatformChannelHandleSwitch)) {
    platform_channel =
        mojo::edk::PlatformChannelPair::PassClientHandleFromParentProcess(
            *base::CommandLine::ForCurrentProcess());
  } else {
    // If this process is elevated, it will have a pipe path passed on the
    // command line.
    platform_channel =
        mojo::edk::NamedPlatformChannelPair::PassClientHandleFromParentProcess(
            *base::CommandLine::ForCurrentProcess());
  }
#elif defined(OS_FUCHSIA)
  platform_channel =
      mojo::edk::PlatformChannelPair::PassClientHandleFromParentProcess(
          *base::CommandLine::ForCurrentProcess());
#elif defined(OS_POSIX)
  platform_channel.reset(mojo::PlatformHandle(
      base::GlobalDescriptors::GetInstance()->Get(kMojoIPCChannel)));
#endif
  // Mojo isn't supported on all child process types.
  // TODO(crbug.com/604282): Support Mojo in the remaining processes.
  if (!platform_channel.is_valid())
    return nullptr;

  return mojo::edk::IncomingBrokerClientInvitation::Accept(
      mojo::edk::ConnectionParams(mojo::edk::TransportProtocol::kLegacy,
                                  std::move(platform_channel)));
}


void DomainMainThread::OnChildControlRequest(
    common::mojom::ChildControlRequest request) {
  child_control_bindings_.AddBinding(this, std::move(request));
}

IPC::MessageRouter* DomainMainThread::GetRouter() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return &router_;
}

bool DomainMainThread::IsGpuCompositingDisabled() const {
  return is_gpu_compositing_disabled_;
}

common::mojom::FrameSinkProvider* DomainMainThread::frame_sink_provider() const {
  return frame_sink_provider_.get();
}

void DomainMainThread::GetInfo(GetInfoCallback callback) {
  
}

void DomainMainThread::GetState(GetStateCallback callback) {

}

}