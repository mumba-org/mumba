// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_APPLICATION_THREAD_H_
#define MUMBA_APPLICATION_APPLICATION_THREAD_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/shared_memory.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/memory_coordinator_client.h"
#include "base/memory/memory_pressure_listener.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/user_metrics_action.h"
#include "base/power_monitor/power_monitor.h"
#include "base/single_thread_task_runner.h"
#include "base/cancelable_callback.h"
#include "base/unguessable_token.h"
#include "base/observer_list.h"
#include "base/optional.h"
#include "base/strings/string16.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "components/variations/child_process_field_trial_syncer.h"
#include "core/shared/common/associated_interfaces.mojom.h"
#include "core/shared/common/child_control.mojom.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/shared/common/mojom/application_message_filter.mojom.h"
#include "core/shared/common/url.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/in_process_child_thread_params.h"
#include "core/shared/common/associated_interface_provider_impl.h"
#include "core/shared/common/associated_interface_registry_impl.h"
//#include "core/shared/common/frame.mojom.h"
#include "core/shared/common/frame_replication_state.h"
#include "core/shared/common/media/renderer_audio_input_stream_factory.mojom.h"
#include "core/shared/common/frame_sink_provider.mojom.h"
//#include "core/shared/common/render_frame_message_filter.mojom.h"
#include "core/shared/common/render_frame_metadata.mojom.h"
//#include "core/shared/common/compositor_helper.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "core/shared/common/service_worker/service_worker_context_instance.h"
#include "core/shared/application/resource_dispatcher_delegate.h"
#include "core/shared/application/child_url_loader_factory_bundle.h"
#include "core/shared/application/media/midi/midi_message_filter.h"
#include "core/shared/application/media/audio/audio_output_ipc_factory.h"
#include "core/shared/application/media/audio/audio_input_ipc_factory.h"
#include "core/shared/application/url_loader_throttle_provider.h"
#include "gpu/ipc/client/gpu_channel_host.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/service_manager/public/cpp/bind_source_info.h"
#include "services/viz/public/interfaces/compositing/compositing_mode_watcher.mojom.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/local_interface_provider.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "services/tracing/public/cpp/trace_event_agent.h"
#include "ipc/ipc.mojom.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_buildflags.h"  // For BUILDFLAG(IPC_MESSAGE_LOG_ENABLED).
#include "ipc/ipc_platform_file.h"
#include "ipc/ipc_sync_channel.h"
#include "ipc/message_router.h"
#include "media/media_buildflags.h"
#include "media/base/routing_token_callback.h"
#include "core/shared/application/media/media_factory.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/thread_safe_interface_ptr.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/effective_connection_type.h"
#include "third_party/blink/public/platform/scheduler/web_main_thread_scheduler.h"
#include "third_party/blink/public/platform/web_connection_type.h"
#include "third_party/blink/public/web/web_memory_statistics.h"
#include "third_party/blink/public/platform/modules/cache_storage/cache_storage.mojom.h"
//#include "ui/gfx/native_widget_types.h"
#include "core/shared/application/layout_test_dependencies.h"
#include "core/shared/common/compositor_dependencies.h"
#include "runtime/MumbaShims/ApplicationHandler.h"
#if defined(OS_WIN)
#include <windows.h>
#include "core/shared/common/font_cache_win.mojom.h"
#elif defined(OS_MACOSX)
#include "mojo/public/cpp/system/buffer.h"
#include "core/shared/common/font_loader_mac.mojom.h"
#endif

class SkBitmap;

namespace IPC {
class MessageFilter;
class SyncChannel;
class SyncMessageFilter;
}  // namespace IPC

namespace mojo {
namespace edk {
class IncomingBrokerClientInvitation;
class OutgoingBrokerClientInvitation;
class ScopedIPCSupport;
}  // namespace edk
}  // namespace mojo

namespace base {
class SingleThreadTaskRunner;
struct UserMetricsAction;
class Thread;
}

namespace service_manager {
class Connector;
}

namespace common {
class ServiceManagerConnection;
class WorkerNativeClientFactory;
}

namespace blink {
class WebMediaPlayerClient;
class WebLocalFrame;
class WebMediaPlayerClient;
class WebMediaPlayerEncryptedMediaClient;
class WebContentDecryptionModule;
class WebString;
class WebLayerTreeView;
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

namespace device {
class Gamepads;
}

namespace discardable_memory {
class ClientDiscardableSharedMemoryManager;
}

namespace gpu {
class GpuChannelHost;
}

namespace media {
class GpuVideoAcceleratorFactories;
class WebMediaPlayerImpl;
}

namespace ui {
class ContextProviderCommandBuffer;
class Gpu;
}

namespace viz {
class BeginFrameSource;
class RasterContextProvider;
class SyntheticBeginFrameSource;
}

namespace application {
class AppCacheDispatcher;
class FileSystemDispatcher;
class NotificationDispatcher;
class ThreadSafeSender;
class ApplicationWindowDispatcher;
class FrameSwapMessageQueue;
class CategorizedWorkerPool;
class BlinkPlatformImpl;
class CompositorHelper;
class GpuVideoAcceleratorFactoriesImpl;
class ResourceDispatcher;
class AudioRendererMixerManager;
class PeerConnectionDependencyFactory;
class PeerConnectionTracker;
class P2PSocketDispatcher;
class AecDumpMessageFilter;
class VideoCaptureImplManager;
class ServiceWorkerMessageFilter;
class AutomationContext;

// Base class for objects that want to filter control IPC messages and get
// notified of events.
class CONTENT_EXPORT ApplicationThreadObserver {
 public:
  ApplicationThreadObserver() {}
  virtual ~ApplicationThreadObserver() {}

  // Allows handling incoming Mojo requests.
  virtual void RegisterMojoInterfaces(
      blink::AssociatedInterfaceRegistry* associated_interfaces) {}
  virtual void UnregisterMojoInterfaces(
      blink::AssociatedInterfaceRegistry* associated_interfaces) {}

  // Allows filtering of control messages.
  virtual bool OnControlMessageReceived(const IPC::Message& message) {
    return false;
  }

  // Called when the network state changes.
  virtual void NetworkStateChanged(bool online) {}

 private:
  DISALLOW_COPY_AND_ASSIGN(ApplicationThreadObserver);
};

class CONTENT_EXPORT ApplicationThread
    : public IPC::Sender,
      public IPC::Listener,
      public common::mojom::RouteProvider,
      public common::mojom::AssociatedInterfaceProvider,
      public common::mojom::ChildControl,
      public service_manager::Service,
      public service_manager::mojom::InterfaceProvider,
      public service_manager::LocalInterfaceProvider,
      public common::mojom::Application,
      public viz::mojom::CompositingModeWatcher,
      //public ChildMemoryCoordinatorDelegate,
      public base::MemoryCoordinatorClient,
      public common::CompositorDependencies {

 public:
  struct CONTENT_EXPORT Options;


  static scoped_refptr<base::SingleThreadTaskRunner> DeprecatedGetMainTaskRunner();

  // Creates the thread.
  ApplicationThread(void* instance_state,
                    int application_process_id,  
                    int application_window_id,
                    const std::string& initial_url,
                    std::unique_ptr<base::MessageLoop> message_loop, 
                    std::unique_ptr<blink::scheduler::WebMainThreadScheduler> scheduler,
                    CWindowCallbacks window_callbacks, 
                    void* window_state,
                    CApplicationCallbacks app_callbacks,
                    bool headless);
  // Allow to be used for single-process mode and for in process gpu mode via
  // options.
  explicit ApplicationThread(
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
      bool headless);
  // ChildProcess::main_thread() is reset after Shutdown(), and before the
  // destructor, so any subsystem that relies on ChildProcess::main_thread()
  // must be terminated before Shutdown returns. In particular, if a subsystem
  // has a thread that post tasks to ChildProcess::main_thread(), that thread
  // should be joined in Shutdown().
  ~ApplicationThread() override;

  //bool Init(const base::CommandLine& cmd);

  void Shutdown();
  
  // Returns true if the thread should be destroyed.
  bool ShouldBeDestroyed();

  // IPC::Sender implementation:
  bool Send(IPC::Message* msg) override;

  service_manager::BinderRegistry* registry() {
    return binder_registry_;//&registry_;
  }

  BlinkPlatformImpl* blink_platform() const {
    return blink_platform_impl_.get();
  }

  // ApplicationThread implementation:
#if defined(OS_WIN)
  void PreCacheFont(const LOGFONT& log_font);
  void ReleaseCachedFonts();
#elif defined(OS_MACOSX)
  bool LoadFont(const base::string16& font_name,
                float font_point_size,
                mojo::ScopedSharedBufferHandle* out_font_data,
                uint32_t* out_font_id);
#endif
  //void RecordAction(const base::UserMetricsAction& action);
  //void RecordComputedAction(const std::string& action);
  common::ServiceManagerConnection* GetServiceManagerConnection();
  service_manager::Connector* GetConnector();
  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner();
  scoped_refptr<base::SingleThreadTaskRunner> GetIPCTaskRunner();
  //void SetFieldTrialGroup(const std::string& trial_name,
  //                        const std::string& group_name);

  // base::FieldTrialList::Observer:
  //void OnFieldTrialGroupFinalized(const std::string& trial_name,
                                  //const std::string& group_name) override;

  IPC::SyncChannel* channel() { return channel_.get(); }

  IPC::MessageRouter* GetRouter();

  common::mojom::RouteProvider* GetRemoteRouteProvider();

  int GenerateRoutingID();

  int routing_id() const {
    return routing_id_; 
  }

  int application_window_id() const {
    return application_window_id_;
  }

  bool IsGpuCompositingDisabled() const { 
    return is_gpu_compositing_disabled_; 
  }
  
  int32_t application_process_id() const {
    return application_process_id_;
  }

  const std::string& initial_url() const {
    return initial_url_;
  }

  bool headless() const {
    return headless_;
  }

  scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner() const {
    return compositor_task_runner_;
  }

  scoped_refptr<ui::ContextProviderCommandBuffer> SharedMainThreadContextProvider();

  // Allocates a block of shared memory of the given size. Returns nullptr on
  // failure.
  static std::unique_ptr<base::SharedMemory> AllocateSharedMemory(
      size_t buf_size);

  std::unique_ptr<base::SharedMemory> HostAllocateSharedMemoryBuffer(size_t size);

  IPC::SyncMessageFilter* sync_message_filter() const {
    return sync_message_filter_.get();
  }

  // The getter should only be called on the main thread, however the
  // IPC::Sender it returns may be safely called on any thread including
  // the main thread.
  ThreadSafeSender* thread_safe_sender() const {
    return thread_safe_sender_.get();
  }

  scoped_refptr<base::SingleThreadTaskRunner> main_thread_runner() const {
    return main_thread_runner_;
  }

  base::MessageLoop* message_loop() const { 
    return message_loop_.get(); 
  }

  ApplicationWindowDispatcher* window_dispatcher() const {
    return window_dispatcher_.get();
  }

  MidiMessageFilter* midi_message_filter() {
    return midi_message_filter_.get();
  }

  AppCacheDispatcher* appcache_dispatcher() const {
    return appcache_dispatcher_.get();
  }

  FileSystemDispatcher* file_system_dispatcher() const {
    return file_system_dispatcher_.get();
  }

  URLLoaderThrottleProvider* url_loader_throttle_provider() const {
    return url_loader_throttle_provider_.get();
  }

  NotificationDispatcher* notification_dispatcher() const {
    return notification_dispatcher_.get();
  }

  void BindWindowDispatcher();

  void DestroyWindowDispatcher(ApplicationWindowDispatcher* window_dispatcher);

  // Returns the one child thread. Can only be called on the main thread.
  static ApplicationThread* current();

#if defined(OS_ANDROID)
  // Called on Android's service thread to shutdown the main thread of this
  // process.
  static void ShutdownThread();
#endif

  void OnProcessFinalRelease();

  void WindowCreated();
  void WindowHidden();
  void WindowRestored();

  ResourceDispatcher* resource_dispatcher() const {
    return resource_dispatcher_.get();
  }

  PeerConnectionTracker* peer_connection_tracker() const {
    return peer_connection_tracker_.get();
  }

  VideoCaptureImplManager* video_capture_impl_manager() const {
    return vc_manager_.get();
  }

  void SetResourceDispatcherDelegate(ResourceDispatcherDelegate* delegate);

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

  bool layout_test_mode() const { return !!layout_test_deps_; }
  void set_layout_test_dependencies(
      std::unique_ptr<LayoutTestDependencies> deps) {
    layout_test_deps_ = std::move(deps);
  }

  // Get the GPU channel. Returns NULL if the channel is not established or
  // has been lost.
  gpu::GpuChannelHost* GetGpuChannel();

  base::TaskRunner* GetWorkerTaskRunner();

  const scoped_refptr<FrameSwapMessageQueue>& frame_swap_message_queue() const {
    return frame_swap_message_queue_;
  }

  std::unique_ptr<cc::SwapPromise> QueueVisualStateResponse(int32_t source_frame_number, uint64_t id);

  // Returns a worker context provider that will be bound on the compositor
  // thread.
  scoped_refptr<viz::RasterContextProvider> SharedCompositorWorkerContextProvider();

  void ScheduleIdleHandler(int64_t initial_delay_ms);
  void IdleHandler();

  scoped_refptr<gpu::GpuChannelHost> EstablishGpuChannelSync();

  media::GpuVideoAcceleratorFactories* GetGpuFactories();

  scoped_refptr<base::SingleThreadTaskRunner> GetMediaThreadTaskRunner();

  common::mojom::RouteRegistry* GetRouteRegistry();

  common::mojom::ChannelRegistry* GetChannelRegistry();

  // the method dont make it clear, but the ownership is up to the caller
  blink::WebMediaPlayer* CreateWebMediaPlayer(
    void* delegate_state,
    WebMediaPlayerDelegateCallbacks callbacks, 
    blink::WebLocalFrame* web_frame,
    const blink::WebMediaPlayerSource& source,
    blink::WebMediaPlayerClient* client,
    blink::WebMediaPlayerEncryptedMediaClient* enc_client,
    blink::WebContentDecryptionModule* mod, 
    blink::WebString sink_id,
    blink::WebLayerTreeView* layer_tree_view,
    const cc::LayerTreeSettings& settings);

  // base::MemoryCoordinatorClient implementation:
  void OnMemoryStateChange(base::MemoryState state) override;
  void OnPurgeMemory() override;

  using LayerTreeFrameSinkCallback =
      base::Callback<void(std::unique_ptr<cc::LayerTreeFrameSink>)>;
  void RequestNewLayerTreeFrameSink(
      int routing_id,
      scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue,
      const GURL& url,
      const LayerTreeFrameSinkCallback& callback,
      common::mojom::RenderFrameMetadataObserverClientRequest
          render_frame_metadata_observer_client_request,
      common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer_ptr);

  std::unique_ptr<cc::SwapPromise> RequestCopyOfOutputForLayoutTest(
      int32_t routing_id,
      std::unique_ptr<viz::CopyOutputRequest> request);

  void OnRequestNewLayerTreeFrameSink(
    void* state,
    void(*cb)(void*, void*),
    std::unique_ptr<cc::LayerTreeFrameSink> result);

  void SetRenderingColorSpace(const gfx::ColorSpace& color_space);

  service_manager::InterfaceProvider* GetRemoteInterfaces();
  blink::AssociatedInterfaceProvider* GetRemoteAssociatedInterfaces();

  // Connect to an interface provided by the service registry.
  template <typename Interface>
  void GetInterface(mojo::InterfaceRequest<Interface> request) {
    GetRemoteInterfaces()->GetInterface(std::move(request));
  }


  bool IsEncryptedMediaEnabled() const;

  AudioRendererMixerManager* GetAudioRendererMixerManager();

  common::mojom::RendererAudioInputStreamFactory* 
    GetAudioInputStreamFactoryForFrame(int frame_id);

  PeerConnectionDependencyFactory* GetPeerConnectionDependencyFactory() {
    return peer_connection_factory_.get();
  }

  void AddObserver(ApplicationThreadObserver* observer);
  void RemoveObserver(ApplicationThreadObserver* observer);

  std::unique_ptr<common::WorkerNativeClientFactory> GetWorkerNativeClientFactory();

  common::ServiceWorkerContextInstance* GetServiceWorkerContextInstance();

  void SetServiceWorkerContextInstance(std::unique_ptr<common::ServiceWorkerContextInstance> instance) {
    service_worker_instance_ = std::move(instance);
  }

  // called by application window dispatcher on behalf of the application runtime
  void OnWebFrameCreated(blink::WebLocalFrame* frame, bool is_main);

 protected:
  //friend class ChildProcess;

  // Called by subclasses to manually start the ServiceManagerConnection. Must
  // only be called if
  // ApplicationThread::Options::auto_start_service_manager_connection was set to
  // |false| on ApplicationThread construction.
  void StartServiceManagerConnection();

  // mojom::ChildControl
  void ProcessShutdown() override;
#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  void SetIPCLoggingEnabled(bool enable) override;
#endif
  void OnChildControlRequest(common::mojom::ChildControlRequest);

  virtual bool OnControlMessageReceived(const IPC::Message& msg);
  // IPC::Listener implementation:
  bool OnMessageReceived(const IPC::Message& msg) override;
  void OnAssociatedInterfaceRequest(
      const std::string& interface_name,
      mojo::ScopedInterfaceEndpointHandle handle) override;
  void OnChannelConnected(int32_t peer_pid) override;
  void OnChannelError() override;
  bool on_channel_error_called() const { return on_channel_error_called_; }

  bool IsInHostProcess() const;

  common::mojom::ApplicationHost* GetApplicationHost();
  //service_manager::Connector* GetConnector();
  void OnApplicationInterfaceRequest(
    common::mojom::ApplicationAssociatedRequest request);


#if defined(OS_MACOSX)
  virtual common::mojom::FontLoaderMac* GetFontLoaderMac();
#endif

  // common::mojom::Application
  void CreateEmbedderApplicationService(
     service_manager::mojom::ServiceRequest service_request) override;
  void GetHandle(GetHandleCallback callback) override;
  void CreateNewWindow(common::mojom::CreateNewWindowParamsPtr params) override;

  // service_manager::Service:
  void OnStart() override;
  void OnBindInterface(
    const service_manager::BindSourceInfo& remote_info,
    const std::string& name,
    mojo::ScopedMessagePipeHandle handle) override;
 
 private:
  friend class ApplicationWindowDispatcher;

  class ApplicationThreadMessageRouter : public IPC::MessageRouter {
   public:
    // |sender| must outlive this object.
    explicit ApplicationThreadMessageRouter(IPC::Sender* sender);
    bool Send(IPC::Message* msg) override;
    void AddFilter(IPC::MessageFilter* filter);
    // MessageRouter overrides.
    bool RouteMessage(const IPC::Message& msg) override;

   private:
    IPC::Sender* const sender_;
  };

  void Init(
    const scoped_refptr<base::SingleThreadTaskRunner>& resource_task_queue,
    const Options& options);

  void RegisterMojoInterfaces();

  // Sets chrome_trace_event_agent_ if necessary.
  void InitTracing();

  // We create the channel first without connecting it so we can add filters
  // prior to any messages being received, then connect it afterwards.
  void ConnectChannel(mojo::edk::IncomingBrokerClientInvitation* invitation);

  // IPC message handlers.

  void EnsureConnected();

  // mojom::RouteProvider:
  void GetRoute(
      int32_t routing_id,
      common::mojom::AssociatedInterfaceProviderAssociatedRequest request) override;

  // mojom::AssociatedInterfaceProvider:
  void GetAssociatedInterface(
      const std::string& name,
      common::mojom::AssociatedInterfaceAssociatedRequest request) override;

#if defined(OS_WIN)
  common::mojom::FontCacheWin* GetFontCacheWin();
#endif

  // service_manager::mojom::InterfaceProvider:
  void GetInterface(const std::string& interface_name,
                   mojo::ScopedMessagePipeHandle interface_pipe) override;

  void BindLocalInterface(
      const std::string& interface_name,
      mojo::ScopedMessagePipeHandle interface_pipe);
  blink::AssociatedInterfaceRegistry* GetAssociatedInterfaceRegistry();

  
  std::unique_ptr<viz::SyntheticBeginFrameSource> CreateSyntheticBeginFrameSource();

  void InitializeCompositorThread();

  void InitializeWebKit(
      const scoped_refptr<base::SingleThreadTaskRunner>& resource_task_queue,
      service_manager::BinderRegistry* registry);

  void ReleaseFreeMemory();

  void LoadResourceBundles();

  bool IsMainThread();

  bool RendererIsHidden() const;
  void OnRendererHidden();
  void OnRendererVisible();

  void CreateNewWindowImpl(common::mojom::CreateNewWindowParamsPtr params);
  
  void RequestOverlayRoutingToken(media::RoutingTokenCallback callback);

  void AddFilter(IPC::MessageFilter* filter);

  int routing_id_;
  int application_window_id_;

  void* instance_state_ = nullptr;
  CApplicationCallbacks app_callbacks_;
      
  std::unique_ptr<base::MessageLoop> message_loop_;

  std::unique_ptr<mojo::edk::ScopedIPCSupport> mojo_ipc_support_;
  std::unique_ptr<common::ServiceManagerConnection> service_manager_connection_;

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

  // Implements message routing functionality to the consumers of
  // ApplicationThread.
  ApplicationThreadMessageRouter router_;

  // The OnChannelError() callback was invoked - the channel is dead, don't
  // attempt to communicate.
  bool on_channel_error_called_;

  // TaskRunner to post tasks to the main thread.
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_runner_;

  std::unique_ptr<ResourceDispatcher> resource_dispatcher_;
  
  std::unique_ptr<base::PowerMonitor> power_monitor_;

  scoped_refptr<base::SingleThreadTaskRunner> host_process_io_runner_;

  std::unique_ptr<tracing::TraceEventAgent> trace_event_agent_;

  //std::unique_ptr<variations::ChildProcessFieldTrialSyncer> field_trial_syncer_;

  std::unique_ptr<base::WeakPtrFactory<ApplicationThread>>
      channel_connected_factory_;

  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

  std::unique_ptr<ApplicationWindowDispatcher> window_dispatcher_;

  common::mojom::ApplicationHostAssociatedPtr application_host_;

  common::AssociatedInterfaceRegistryImpl associated_interfaces_;
  std::unique_ptr<common::AssociatedInterfaceProviderImpl> remote_associated_interfaces_;

  mojo::BindingSet<service_manager::mojom::InterfaceProvider> interface_provider_bindings_;
  mojo::AssociatedBinding<common::mojom::Application> application_binding_;

  int32_t application_process_id_;

  common::mojom::ApplicationMessageFilterAssociatedPtr application_message_filter_;

  std::unique_ptr<service_manager::Connector> connector_;
  service_manager::mojom::ConnectorRequest connector_request_;
  std::unique_ptr<service_manager::ServiceContext> service_context_;
  //service_manager::BinderRegistry registry_;
  service_manager::InterfaceProvider remote_interfaces_;

  std::unique_ptr<discardable_memory::ClientDiscardableSharedMemoryManager>
      discardable_shared_memory_manager_;

  std::unique_ptr<blink::scheduler::WebMainThreadScheduler>
      main_thread_scheduler_;

  std::unique_ptr<BlinkPlatformImpl> blink_platform_impl_;    

  // Used to control layout test specific behavior.
  std::unique_ptr<LayoutTestDependencies> layout_test_deps_;

  // Timer that periodically calls IdleHandler.
  base::RepeatingTimer idle_timer_;

  // Will point to appropriate task runner after initialization,
  // regardless of whether |compositor_thread_| is overriden.
  scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner_;
  // Pool of workers used for raster operations (e.g., tile rasterization).
  scoped_refptr<CategorizedWorkerPool> categorized_worker_pool_;

  scoped_refptr<ui::ContextProviderCommandBuffer> shared_main_thread_contexts_;

  scoped_refptr<viz::RasterContextProvider> shared_worker_context_provider_;

  service_manager::BinderRegistry* binder_registry_;

  //std::unique_ptr<ChildMemoryCoordinatorImpl> memory_coordinator_;

  std::unique_ptr<ui::Gpu> gpu_;

  scoped_refptr<base::SingleThreadTaskRunner> main_thread_compositor_task_runner_;
  
  bool is_gpu_compositing_disabled_ = false;
  // The count of ApplicationWidgets running through this thread.
  int widget_count_ = 0;
  // The count of hidden ApplicationWidgets running through this thread.
  int hidden_widget_count_ = 0;
  // The current value of the idle notification timer delay.
  int64_t idle_notification_delay_in_ms_ = 0;
  // The number of idle handler calls that skip sending idle notifications.
  int idle_notifications_to_skip_ = 0;
  bool webkit_shared_timer_suspended_ = false;


  bool is_gpu_rasterization_forced_ = false;
  int gpu_rasterization_msaa_sample_count_ = -1;
  bool is_lcd_text_enabled_ = true;
  bool is_zero_copy_enabled_ = true;
  bool is_gpu_memory_buffer_compositor_resources_enabled_ = true;
  bool is_partial_raster_enabled_ = true;
  bool is_elastic_overscroll_enabled_ = false;
  bool is_threaded_animation_enabled_ = true;
  bool is_scroll_animator_enabled_ = false;

  std::string initial_url_;
  std::string application_name_;

  gfx::ColorSpace rendering_color_space_;

  std::vector<std::pair<blink::WebLocalFrame*, std::unique_ptr<MediaFactory>>> media_factories_;
  std::unordered_map<int, common::mojom::RendererAudioInputStreamFactoryPtr> audio_input_stream_factories_;


  std::unique_ptr<AppCacheDispatcher> appcache_dispatcher_;
  std::unique_ptr<FileSystemDispatcher> file_system_dispatcher_;
  scoped_refptr<ServiceWorkerMessageFilter> service_worker_message_filter_;
  scoped_refptr<NotificationDispatcher> notification_dispatcher_;
  std::unique_ptr<URLLoaderThrottleProvider> url_loader_throttle_provider_;

  std::unique_ptr<AudioRendererMixerManager> audio_renderer_mixer_manager_;

  // AndroidOverlay routing token from the browser, if we have one yet.
  base::Optional<base::UnguessableToken> overlay_routing_token_;

  // Callbacks that we should call when we get a routing token.
  std::vector<media::RoutingTokenCallback> pending_routing_token_callbacks_;

   // Provides AudioInputIPC objects for audio input devices. Initialized in
  // Init.
  base::Optional<AudioInputIPCFactory> audio_input_ipc_factory_;
  // Provides AudioOutputIPC objects for audio output devices. Initialized in
  // Init.
  base::Optional<AudioOutputIPCFactory> audio_output_ipc_factory_;

  scoped_refptr<MidiMessageFilter> midi_message_filter_;

  common::mojom::FrameSinkProviderPtr frame_sink_provider_;
  // A mojo connection to the CompositingModeReporter service.
  viz::mojom::CompositingModeReporterPtr compositing_mode_reporter_;
  // The class is a CompositingModeWatcher, which is bound to mojo through
  // this member.
  mojo::Binding<viz::mojom::CompositingModeWatcher>
      compositing_mode_watcher_binding_;

  std::unique_ptr<common::CompositorHelper> compositor_helper_;    

  std::unique_ptr<blink::scheduler::WebThreadBase> compositor_thread_;

  std::vector<std::unique_ptr<GpuVideoAcceleratorFactoriesImpl>> gpu_factories_;

  scoped_refptr<FrameSwapMessageQueue> frame_swap_message_queue_;

  base::ObserverList<ApplicationThreadObserver> observers_;

  std::unique_ptr<PeerConnectionDependencyFactory> peer_connection_factory_;
  std::unique_ptr<PeerConnectionTracker> peer_connection_tracker_;

  scoped_refptr<P2PSocketDispatcher> p2p_socket_dispatcher_;
  scoped_refptr<AecDumpMessageFilter> aec_dump_message_filter_;
  std::unique_ptr<VideoCaptureImplManager> vc_manager_;

  common::mojom::RouteRegistryAssociatedPtr route_registry_interface_;
  common::mojom::ChannelRegistryAssociatedPtr channel_registry_interface_;

  // Thread for running multimedia operations (e.g., video decoding).
  std::unique_ptr<base::Thread> media_thread_;

  std::unique_ptr<common::ServiceWorkerContextInstance> service_worker_instance_;

  std::unique_ptr<AutomationContext> automation_context_;

  bool headless_;

  base::WeakPtrFactory<ApplicationThread> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationThread);
};

struct ApplicationThread::Options {
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

class ApplicationThread::Options::Builder {
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
