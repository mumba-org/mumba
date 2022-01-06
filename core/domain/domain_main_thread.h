// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_MAIN_THREAD_H_
#define MUMBA_DOMAIN_DOMAIN_MAIN_THREAD_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/template_util.h"
#include "base/command_line.h"
#include "base/files/file.h"
#include "base/memory/shared_memory.h"
#include "base/memory/memory_coordinator_client.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_listener.h"
#include "ipc/ipc_platform_file.h"
#include "ipc/message_router.h"
#include "ipc/ipc_channel_proxy.h"
#include "base/uuid.h"
#include "core/shared/common/url.h"
#include "core/common/common_data.h"
#include "core/common/request_codes.h"
#include "core/shared/common/child_thread_impl.h"
#include "core/shared/common/associated_interface_provider_impl.h"
#include "core/shared/common/associated_interface_registry_impl.h"
#include "core/shared/common/mojom/domain.mojom.h"
#include "core/shared/common/mojom/domain.mojom.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "core/shared/common/mojom/domain_message_filter.mojom.h"
#include "core/shared/common/compositor_dependencies.h"
#include "core/shared/common/service_worker/service_worker_context_instance.h"
#include "core/shared/common/frame_replication_state.h"
#include "core/shared/common/media/renderer_audio_input_stream_factory.mojom.h"
#include "core/shared/common/frame_sink_provider.mojom.h"
#include "core/shared/common/render_frame_metadata.mojom.h"
#include "core/domain/domain_context.h"
#include "core/domain/main_shadow_page_delegate.h"
#include "core/domain/layout_test_dependencies.h"
#include "core/domain/layer_tree_view_delegate.h"
#include "core/shared/domain/net/socket_dispatcher.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/viz/public/interfaces/compositing/compositing_mode_watcher.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/local_interface_provider.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "components/viz/common/features.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/common/frame_sinks/copy_output_request.h"
#include "components/viz/common/switches.h"
#include "core/shared/common/in_process_child_thread_params.h"
#include "gpu/command_buffer/service/gpu_switches.h"
#include "ipc/ipc_message_start.h"
#include "ipc/ipc_sync_message.h"
#include "ipc/ipc_sync_message_filter.h"
#include "media/base/media_switches.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/platform/scheduler/web_main_thread_scheduler.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/web_render_widget_scheduling_state.h"
#include "third_party/blink/public/platform/scheduler/web_thread_scheduler.h"
#include "third_party/blink/public/platform/web_cursor_info.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/public/platform/web_drag_operation.h"
#include "third_party/blink/public/platform/web_mouse_event.h"
#include "third_party/blink/public/platform/web_point.h"
#include "third_party/blink/public/platform/web_rect.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/platform/web_size.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_device_emulation_params.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_input_method_controller.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_page_popup.h"
#include "third_party/blink/public/web/web_popup_menu_info.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/public/web/web_widget.h"
#include "third_party/skia/include/core/SkShader.h"
#include "ui/base/ui_base_features.h"
#include "ui/base/ui_base_switches.h"
#include "ui/events/base_event_utils.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/skia_util.h"
#include "ui/gfx/switches.h"
#include "ui/gl/gl_switches.h"
#include "ui/native_theme/native_theme_features.h"
#include "ui/native_theme/overlay_scrollbar_constants_aura.h"
#include "ui/surface/transport_dib.h"

namespace IPC {
class SyncChannel;
class SyncMessageFilter;
class MessageFilter;
}  // namespace IPC

namespace common {
class WorkerNativeClientFactory;
namespace mojom {
class StorageDispatcherHost;  
}  
}

namespace discardable_memory {
class ClientDiscardableSharedMemoryManager;
}

namespace blink {
namespace scheduler {
class WebThreadBase;
}
}

namespace cc {
class BeginFrameSource;
class LayerTreeFrameSink;
class LayerTreeSettings;
class SyntheticBeginFrameSource;
class TaskGraphRunner;
class SwapPromise;
}

namespace ui {
class ContextProviderCommandBuffer;
class Gpu;
}

namespace gpu {
class GpuChannelHost;
}

namespace media {
class GpuVideoAcceleratorFactories;
}

namespace viz {
class BeginFrameSource;
class RasterContextProvider;
class SyntheticBeginFrameSource;
}

namespace domain {
class DomainThread;
class DomainProcess;
class P2PSocketDispatcher;
class ThreadSafeSender;
class ResourceDispatcher;
class ResourceDispatcherDelegate;
class BlinkPlatformImpl;
class ServiceWorkerMessageFilter;
class NotificationDispatcher;
class AppCacheDispatcher;
class FileSystemDispatcher;
class CategorizedWorkerPool;
class FrameSwapMessageQueue;
class LayerTreeView;
class MainShadowPage;

class DomainMainThread :  public IPC::Sender,
                          public IPC::Listener,
                          public common::mojom::RouteProvider,
                          public common::mojom::AssociatedInterfaceProvider,
                          public common::mojom::ChildControl,
                          public common::mojom::Domain,
                          public service_manager::Service,
                          public service_manager::mojom::InterfaceProvider,
                          public service_manager::LocalInterfaceProvider,
                          public viz::mojom::CompositingModeWatcher,
                          public base::MemoryCoordinatorClient,
                          public MainShadowPageDelegate {
                          
public:
  struct CONTENT_EXPORT Options;

  static DomainMainThread* Create(
    std::unique_ptr<base::MessageLoop> message_loop,
    std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
    const base::CommandLine& cmd,
    const base::FilePath& domain_root,
    const base::UUID& domain_id,
    const std::string& domain_name,
    const std::string& bundle_path,
    int process_id);

  static DomainMainThread* current();

  static scoped_refptr<base::SingleThreadTaskRunner> DeprecatedGetMainTaskRunner();

  explicit DomainMainThread(
    std::unique_ptr<base::MessageLoop> message_loop,
    std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
    const base::CommandLine& cmd,
    const base::FilePath& domain_root,
    const base::UUID& domain_id,
    const std::string& domain_name,
    const std::string& bundle_path,
    int process_id,
    const Options& options);

  ~DomainMainThread() override;

  void Init(const base::CommandLine& cmd,
            const Options& options);
  void Shutdown() override;
  // IPC::Sender implementation:
  bool Send(IPC::Message* msg) override;

  service_manager::BinderRegistry* registry() {
    return &registry_;
  }

  scoped_refptr<DomainContext> domain_context() const {
  return domain_context_;
  }

  scoped_refptr<P2PSocketDispatcher> p2p_socket_dispatcher() const {
   return p2p_socket_dispatcher_;
  }

  common::mojom::StorageDispatcherHost* GetStorageDispatcherHost();

  ResourceDispatcher* resource_dispatcher() const {
    return resource_dispatcher_.get();
  }

  bool layout_test_mode() const { return !!layout_test_deps_; }
  void set_layout_test_dependencies(
      std::unique_ptr<LayoutTestDependencies> deps) {
    layout_test_deps_ = std::move(deps);
  }

  void SetResourceDispatcherDelegate(ResourceDispatcherDelegate* delegate);

   // IPC::Listener
  bool OnMessageReceived(const IPC::Message& msg) override;
  void OnAssociatedInterfaceRequest(
      const std::string& name,
      mojo::ScopedInterfaceEndpointHandle handle) override;
  void OnChannelConnected(int32_t peer_pid) override;
  void OnChannelError() override;
  bool on_channel_error_called() const { return on_channel_error_called_; }

  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner();
  scoped_refptr<base::SingleThreadTaskRunner> GetIPCTaskRunner();
  IPC::SyncChannel* GetChannel();
  IPC::SyncMessageFilter* GetSyncMessageFilter();
  IPC::MessageRouter* GetRouter();
  base::MessageLoop* message_loop() const { 
    return message_loop_.get(); 
  }
  void AddRoute(int32_t routing_id, IPC::Listener* listener);
  void RemoveRoute(int32_t routing_id);
  int GenerateRoutingID();
  void AddFilter(IPC::MessageFilter* filter);
  void RemoveFilter(IPC::MessageFilter* filter);
  common::mojom::DomainHost* GetDomainHost();
  common::mojom::RouteRegistry* GetRouteRegistry();
  service_manager::Connector* GetConnector();
  void OnDomainInterfaceRequest(
    common::mojom::DomainAssociatedRequest request);

  common::mojom::DomainMessageFilter* domain_message_filter();
  scoped_refptr<base::SingleThreadTaskRunner> GetMainTaskRunner();

  // common::mojom::Domain
  void CreateEmbedderDomainService(
     service_manager::mojom::ServiceRequest service_request) override;
  void GetHandle(GetHandleCallback callback) override;

  // service_manager::Service:
  void OnStart() override;
  void OnBindInterface(
    const service_manager::BindSourceInfo& remote_info,
    const std::string& name,
    mojo::ScopedMessagePipeHandle handle) override;

  ThreadSafeSender* thread_safe_sender() const {
    return thread_safe_sender_.get();
  }

  IPC::SyncMessageFilter* sync_message_filter() const {
    return sync_message_filter_.get();
  }
  
  BlinkPlatformImpl* blink_platform() const {
    return blink_platform_impl_.get();
  }

  AppCacheDispatcher* appcache_dispatcher() const {
    return appcache_dispatcher_.get();
  }

  FileSystemDispatcher* file_system_dispatcher() const {
    return file_system_dispatcher_.get();
  }

  NotificationDispatcher* notification_dispatcher() const {
    return notification_dispatcher_.get();
  }

  // Allocates a block of shared memory of the given size. Returns nullptr on
  // failure.
  static std::unique_ptr<base::SharedMemory> AllocateSharedMemory(
      size_t buf_size);

  std::unique_ptr<base::SharedMemory> HostAllocateSharedMemoryBuffer(size_t size);

  std::unique_ptr<common::WorkerNativeClientFactory> GetWorkerNativeClientFactory();

  common::ServiceWorkerContextInstance* GetServiceWorkerContextInstance();

  void SetServiceWorkerContextInstance(std::unique_ptr<common::ServiceWorkerContextInstance> instance) {
    service_worker_instance_ = std::move(instance);
  }

  scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner() const {
    return compositor_task_runner_;
  }
  scoped_refptr<ui::ContextProviderCommandBuffer> SharedMainThreadContextProvider();

  // CompositorDependencies impl
  bool IsGpuRasterizationForced() override;
  int GetGpuRasterizationMSAASampleCount() override;
  bool IsLcdTextEnabled() override;
  bool IsZeroCopyEnabled() override;
  bool IsPartialRasterEnabled() override;
  bool IsGpuMemoryBufferCompositorResourcesEnabled() override;
  bool IsElasticOverscrollEnabled() override;
  scoped_refptr<base::SingleThreadTaskRunner> GetCompositorMainThreadTaskRunner() override;
  scoped_refptr<base::SingleThreadTaskRunner> GetCompositorImplThreadTaskRunner() override;
  blink::scheduler::WebMainThreadScheduler* GetWebMainThreadScheduler() override;
  gpu::GpuMemoryBufferManager* GetGpuMemoryBufferManager() override;
  cc::TaskGraphRunner* GetTaskGraphRunner() override;
  bool IsThreadedAnimationEnabled() override;
  bool IsScrollAnimatorEnabled() override;
  std::unique_ptr<cc::UkmRecorderFactory> CreateUkmRecorderFactory() override;
  viz::SharedBitmapManager* GetSharedBitmapManager() override;
  gpu::ImageFactory* GetImageFactory() override;
  common::CompositorHelper* compositor_helper() override;
  void CompositingModeFallbackToSoftware() override;

  void OnMainShadowPageInitialized() override;
  std::unique_ptr<blink::WebApplicationCacheHost> CreateApplicationCacheHost(blink::WebApplicationCacheHostClient*) override;
  const base::UnguessableToken& GetDevToolsWorkerToken() override;

   // Get the GPU channel. Returns NULL if the channel is not established or
  // has been lost.
  gpu::GpuChannelHost* GetGpuChannel();

  const scoped_refptr<FrameSwapMessageQueue>& frame_swap_message_queue() const {
    return frame_swap_message_queue_;
  }

  std::unique_ptr<cc::SwapPromise> QueueVisualStateResponse(int32_t source_frame_number, uint64_t id);

  // Returns a worker context provider that will be bound on the compositor
  // thread.
  scoped_refptr<viz::RasterContextProvider> SharedCompositorWorkerContextProvider() override;
  scoped_refptr<gpu::GpuChannelHost> EstablishGpuChannelSync() override;

  //media::GpuVideoAcceleratorFactories* GetGpuFactories();

  void OnMemoryStateChange(base::MemoryState state) override;
  void OnPurgeMemory() override;

  // using LayerTreeFrameSinkCallback =
  //     base::Callback<void(std::unique_ptr<cc::LayerTreeFrameSink>)>;
  // void RequestNewLayerTreeFrameSink(
  //     int routing_id,
  //     scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue,
  //     const GURL& url,
  //     const LayerTreeFrameSinkCallback& callback,
  //     common::mojom::RenderFrameMetadataObserverClientRequest
  //         render_frame_metadata_observer_client_request,
  //     common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer_ptr);

  // void OnRequestNewLayerTreeFrameSink(
  //   void* state,
  //   void(*cb)(void*, void*),
  //   std::unique_ptr<cc::LayerTreeFrameSink> result);

  void SetRenderingColorSpace(const gfx::ColorSpace& color_space);

  std::unique_ptr<cc::SwapPromise> RequestCopyOfOutputForLayoutTest(std::unique_ptr<viz::CopyOutputRequest> request) override;

  common::ServiceManagerConnection* GetServiceManagerConnection();
  IPC::SyncChannel* channel() { return channel_.get(); }
  common::mojom::RouteProvider* GetRemoteRouteProvider();

  int domain_process_id() const {
    return process_id_;
  }

  bool IsGpuCompositingDisabled() const;

  common::mojom::FrameSinkProvider* frame_sink_provider() const override;
  
private:
  friend class DomainHost;

  class DomainMainThreadMessageRouter : public IPC::MessageRouter {
   public:
    // |sender| must outlive this object.
    explicit DomainMainThreadMessageRouter(IPC::Sender* sender);
    bool Send(IPC::Message* msg) override;
    void AddFilter(IPC::MessageFilter* filter);
    // MessageRouter overrides.
    bool RouteMessage(const IPC::Message& msg) override;

   private:
    IPC::Sender* const sender_;
  };

  void RegisterMojoInterfaces();

  // service_manager::mojom::InterfaceProvider:
  void GetInterface(const std::string& interface_name,
                   mojo::ScopedMessagePipeHandle interface_pipe) override;

  void BindLocalInterface(
      const std::string& interface_name,
      mojo::ScopedMessagePipeHandle interface_pipe);
  service_manager::InterfaceProvider* GetRemoteInterfaces();
  blink::AssociatedInterfaceRegistry* GetAssociatedInterfaceRegistry();
  blink::AssociatedInterfaceProvider* GetRemoteAssociatedInterfaces();

  void OnProcessFinalRelease();

  void InitializeWebKit(
    const scoped_refptr<base::SingleThreadTaskRunner>& resource_task_queue,
    service_manager::BinderRegistry* registry);
  
  void InitializeWebKitOnIOThread();

  virtual bool OnControlMessageReceived(const IPC::Message& msg);

  void ScheduleIdleHandler(int64_t initial_delay_ms);
  void IdleHandler();
  void ReleaseFreeMemory();

  void InitializeCompositorThread();

  void LoadResourceBundles();

  void InitTracing();

  // We create the channel first without connecting it so we can add filters
  // prior to any messages being received, then connect it afterwards.
  void ConnectChannel(mojo::edk::IncomingBrokerClientInvitation* invitation);

  void EnsureConnected();

  void StartServiceManagerConnection();

#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  void SetIPCLoggingEnabled(bool enable) override;
#endif

  bool IsInHostProcess() const;

  // mojom::RouteProvider:
  void GetRoute(
      int32_t routing_id,
      common::mojom::AssociatedInterfaceProviderAssociatedRequest request) override;

  // mojom::AssociatedInterfaceProvider:
  void GetAssociatedInterface(
      const std::string& name,
      common::mojom::AssociatedInterfaceAssociatedRequest request) override;

  void ProcessShutdown() override;

  std::unique_ptr<mojo::edk::IncomingBrokerClientInvitation> InitializeMojoIPCChannel();
  void OnChildControlRequest(common::mojom::ChildControlRequest);

  void GetInfo(GetInfoCallback callback) override;
  void GetState(GetStateCallback callback) override;
  
  base::FilePath channel_path_;
  
  int process_id_;
  int routing_id_;

  std::string bundle_path_;

  scoped_refptr<P2PSocketDispatcher> p2p_socket_dispatcher_;

  std::unique_ptr<base::MessageLoop> message_loop_;

  std::unique_ptr<DomainThread> main_thread_;

  common::mojom::DomainHostAssociatedPtr domain_host_;

  std::unique_ptr<mojo::edk::ScopedIPCSupport> mojo_ipc_support_;
  std::unique_ptr<common::ServiceManagerConnection> service_manager_connection_;

  common::AssociatedInterfaceRegistryImpl associated_interfaces_;
  std::unique_ptr<common::AssociatedInterfaceProviderImpl> remote_associated_interfaces_;

  mojo::BindingSet<service_manager::mojom::InterfaceProvider> interface_provider_bindings_;
  mojo::AssociatedBinding<common::mojom::Domain> domain_binding_;

  common::mojom::DomainMessageFilterAssociatedPtr domain_message_filter_;

  std::unique_ptr<service_manager::Connector> connector_;
  service_manager::mojom::ConnectorRequest connector_request_;
  std::unique_ptr<service_manager::ServiceContext> service_context_;
  service_manager::BinderRegistry registry_;
  service_manager::InterfaceProvider remote_interfaces_;

  scoped_refptr<DomainContext> domain_context_;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_compositor_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner_;
  std::unique_ptr<blink::scheduler::WebMainThreadScheduler> main_thread_scheduler_;
  std::unique_ptr<blink::scheduler::WebThreadBase> compositor_thread_;

  mojo::BindingSet<common::mojom::ChildControl> child_control_bindings_;
  mojo::AssociatedBinding<common::mojom::RouteProvider> route_provider_binding_;
  mojo::AssociatedBindingSet<common::mojom::AssociatedInterfaceProvider, int32_t>
      associated_interface_provider_bindings_;
  common::mojom::RouteProviderAssociatedPtr remote_route_provider_;
#if defined(OS_WIN)
  common::mojom::FontCacheWinPtr font_cache_win_ptr_;
#elif defined(OS_MACOSX)
  common::mojom::FontLoaderMacPtr font_loader_mac_ptr_;
#endif

  std::unique_ptr<IPC::SyncChannel> channel_;
  // Allows threads other than the main thread to send sync messages.
  scoped_refptr<IPC::SyncMessageFilter> sync_message_filter_;
  scoped_refptr<ThreadSafeSender> thread_safe_sender_;

  std::unique_ptr<discardable_memory::ClientDiscardableSharedMemoryManager> discardable_shared_memory_manager_;

  std::unique_ptr<ResourceDispatcher> resource_dispatcher_;

  std::unique_ptr<BlinkPlatformImpl> blink_platform_impl_;

  // Timer that periodically calls IdleHandler.
  base::RepeatingTimer idle_timer_;

  scoped_refptr<ServiceWorkerMessageFilter> service_worker_message_filter_;
  scoped_refptr<NotificationDispatcher> notification_dispatcher_;
  std::unique_ptr<AppCacheDispatcher> appcache_dispatcher_;
  std::unique_ptr<FileSystemDispatcher> file_system_dispatcher_;

  std::unique_ptr<common::ServiceWorkerContextInstance> service_worker_instance_;

  bool initialized_;
  bool webkit_shared_timer_suspended_ = false;
  int64_t idle_notification_delay_in_ms_ = 0;

  std::unique_ptr<ui::Gpu> gpu_;

  // Used to control layout test specific behavior.
  std::unique_ptr<LayoutTestDependencies> layout_test_deps_;
  // Pool of workers used for raster operations (e.g., tile rasterization).
  scoped_refptr<CategorizedWorkerPool> categorized_worker_pool_;

  scoped_refptr<ui::ContextProviderCommandBuffer> shared_main_thread_contexts_;

  scoped_refptr<viz::RasterContextProvider> shared_worker_context_provider_;

  bool is_gpu_compositing_disabled_ = false;
  // The number of idle handler calls that skip sending idle notifications.
  int idle_notifications_to_skip_ = 0;

  bool is_gpu_rasterization_forced_ = false;
  int gpu_rasterization_msaa_sample_count_ = -1;
  bool is_lcd_text_enabled_ = true;
  bool is_zero_copy_enabled_ = true;
  bool is_gpu_memory_buffer_compositor_resources_enabled_ = true;
  bool is_partial_raster_enabled_ = true;
  bool is_elastic_overscroll_enabled_ = false;
  bool is_threaded_animation_enabled_ = true;
  bool is_scroll_animator_enabled_ = false;

  gfx::ColorSpace rendering_color_space_;

  common::mojom::FrameSinkProviderPtr frame_sink_provider_;
  // A mojo connection to the CompositingModeReporter service.
  viz::mojom::CompositingModeReporterPtr compositing_mode_reporter_;
  // The class is a CompositingModeWatcher, which is bound to mojo through
  // this member.
  mojo::Binding<viz::mojom::CompositingModeWatcher>
      compositing_mode_watcher_binding_;

  std::unique_ptr<common::CompositorHelper> compositor_helper_;

  //std::vector<std::unique_ptr<GpuVideoAcceleratorFactoriesImpl>> gpu_factories_;
  scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue_;

  std::unique_ptr<MainShadowPage> main_shadow_page_;

  scoped_refptr<base::SingleThreadTaskRunner> host_process_io_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

  bool on_channel_error_called_;

  base::UnguessableToken devtools_worker_token_;
  
  base::WaitableEvent wait_on_blink_io_init_;

  // Implements message routing functionality to the consumers of
  // DomainMainThread.
  DomainMainThreadMessageRouter router_;

  std::unique_ptr<base::WeakPtrFactory<DomainMainThread>>
      channel_connected_factory_;

  base::WeakPtrFactory<DomainMainThread> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(DomainMainThread);
};

struct DomainMainThread::Options {
  Options(const Options& other);
  ~Options();

  class Builder;

  bool auto_start_service_manager_connection;
  bool connect_to_browser;
  scoped_refptr<base::SingleThreadTaskRunner> host_process_io_runner;
  std::vector<IPC::MessageFilter*> startup_filters;
  mojo::edk::OutgoingBrokerClientInvitation* broker_client_invitation;
  std::string in_process_service_request_token;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner;

 private:
  Options();
};

class DomainMainThread::Options::Builder {
 public:
  Builder();

  Builder& InBrowserProcess(const common::InProcessChildThreadParams& params);
  Builder& AutoStartServiceManagerConnection(bool auto_start);
  Builder& ConnectToBrowser(bool connect_to_browser);
  Builder& AddStartupFilter(IPC::MessageFilter* filter);
  Builder& IPCTaskRunner(
      scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner);

  Options Build();

 private:
  struct Options options_;

  DISALLOW_COPY_AND_ASSIGN(Builder);
};

}

#endif
