// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_PROCESS_HOST_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_PROCESS_HOST_H_

#include <memory>

#include "base/macros.h"
#include "base/callback.h"
#include "base/atomic_sequence_num.h"
#include "base/containers/id_map.h"
#include "base/observer_list.h"
#include "base/macros.h"
#include "base/supports_user_data.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_listener.h"
#include "ipc/ipc_channel_proxy.h"
#include "core/common/common_data.h"
#include "core/common/request_codes.h"
#include "core/common/process_launcher_delegate.h"
#include "core/shared/common/associated_interface_registry_impl.h"
#include "core/shared/common/associated_interfaces.mojom.h"
#include "core/shared/common/child_control.mojom.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/associated_interface_registry_impl.h"
#include "core/shared/common/associated_interfaces.mojom.h"
#include "core/shared/common/bind_interface_helpers.h"
#include "core/host/application/frame_sink_provider_impl.h"
//#include "core/host/application/embedded_frame_sink_provider_impl.h"
#include "core/host/application/offscreen_canvas_provider_impl.h"
#include "core/host/application/runnable_process.h"
#include "core/shared/common/mojom/window.mojom.h"
#include "core/host/child_process_launcher.h"
#include "core/host/cache_storage/cache_storage_dispatcher_host.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "mojo/edk/embedder/outgoing_broker_client_invitation.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/mojom/service.mojom.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "services/viz/public/interfaces/compositing/compositing_mode_watcher.mojom.h"
#include "ui/gfx/gpu_memory_buffer.h"
#include "ui/gl/gpu_switching_observer.h"

namespace net {
class URLRequestContextGetter;  
class HostResolver;
class CertVerifier;
class MultiLogCTVerifier;
}

namespace common {
class ChildConnection;
}

namespace resource_coordinator {
class ProcessResourceCoordinator;
}

namespace host {
class Application;
class Domain;
class ApplicationWindowHost;
class HostMessageFilter;
class IOThread;
class MojoDomainPoolService;
class ApplicationProcessHostObserver;
class ApplicationWindowHostDelegate;
class ApplicationWindowHelper;
class HostMessageFilter;
class GpuClient;
class RendererAudioOutputStreamFactoryContext;
class RendererAudioOutputStreamFactoryContextImpl;
class HostNetworkContext;
class HostNetworkDelegate;
class BackgroundFetchContext;
class ResourceMessageFilter;
class P2PSocketDispatcherHost;
class PeerConnectionTrackerHost;
class NotificationMessageFilter;
class ApplicationDriver;

class ApplicationProcessHost  : public IPC::Sender,
                                public IPC::Listener,
                                public RunnableProcess,
                                public ui::GpuSwitchingObserver,
                                public common::mojom::RouteProvider,
                                public common::mojom::AssociatedInterfaceProvider,
                                public ChildProcessLauncher::Client,
                                public common::mojom::ApplicationHost,
                                public base::SupportsUserData {
public:
  using iterator = base::IDMap<ApplicationProcessHost*>::iterator;
  // class Observer {
  // public:
  //   virtual void ApplicationProcessReady(ApplicationProcessHost* host) {}
  //   virtual void ApplicationProcessShutdownRequested(ApplicationProcessHost* host) {}
  //   virtual void ApplicationProcessWillExit(ApplicationProcessHost* host) {}
  //   virtual void ApplicationProcessExited(ApplicationProcessHost* host,
  //                                  const ChildProcessTerminationInfo& info) {}
  //   virtual void ApplicationProcessHostDestroyed(ApplicationProcessHost* host) {}
  // protected:
  //   virtual ~Observer() {}
  // };
  static iterator AllHostsIterator();
  static ApplicationProcessHost* FromID(int32_t process_id);

  ApplicationProcessHost(base::WeakPtr<Application> application);
  ~ApplicationProcessHost() override;

  const base::FilePath& application_root() const {
    return application_root_;
  }

  const base::FilePath& application_executable() const {
    return application_executable_;
  }

  NotificationMessageFilter* notification_message_filter() const {
    return notification_message_filter_.get();
  }

  // RunnableProcess
  Domain* domain() const override {
    return domain_;
  }
  Runnable* runnable() const override;
  int GetID() const override;
  const base::Process& GetProcess() const override;
  IPC::ChannelProxy* GetChannelProxy() override;
  common::mojom::Application* GetApplicationInterface() override;
  bool Shutdown(int exit_code) override;
  
  const scoped_refptr<base::SingleThreadTaskRunner>& loader_task_runner() const {
    return loader_task_runner_;
  }

  bool Init();
  void EnableSendQueue();
  common::mojom::ApplicationWindow* GetApplicationWindowInterface();
  common::mojom::RouteProvider* GetRemoteRouteProvider();
  int GetNextRoutingID();

  ApplicationWindowHost* application_window_host() const {
    return application_window_host_.get();
  }

  bool HasConnection() const;
  bool IsReady() const;

  const service_manager::Identity& GetChildIdentity() const;
  HostNetworkContext* GetNetworkContext() const {
    return network_context_.get();
  }

  void AddRoute(int32_t routing_id, IPC::Listener* listener);
  void RemoveRoute(int32_t routing_id);

  void Cleanup();
  
  // Sender
  bool Send(IPC::Message* msg) override;

  // ChildProcessLauncher
  void OnProcessLaunched() override;
  void OnProcessLaunchFailed(int error_code) override;
 
  // Receiver
  bool OnMessageReceived(const IPC::Message& message) override;
  void OnChannelConnected(int32_t peer_pid) override;
  void OnChannelError() override;
  void OnBadMessageReceived(const IPC::Message& message) override;

  void BindInterface(const std::string& interface_name,
                     mojo::ScopedMessagePipeHandle interface_pipe);

  void AddFilter(HostMessageFilter* filter);

  static void RegisterHost(int host_id, ApplicationProcessHost* host);
  static void UnregisterHost(int host_id);

  void AddWindow(ApplicationWindowHost* window);
  void RemoveWindow(ApplicationWindowHost* window);

  void AddObserver(ApplicationProcessHostObserver* observer);
  void RemoveObserver(ApplicationProcessHostObserver* observer);

  void OnMediaStreamAdded();
  void OnMediaStreamRemoved();

  void SetSuddenTerminationAllowed(bool enabled);
  bool SuddenTerminationAllowed() const;

  static void ReleaseOnCloseACK(ApplicationProcessHost* host, int view_route_id);

  void PostTaskWhenProcessIsReady(base::OnceClosure task);

  bool IgnoreInputEvents() const;
  void SetIgnoreInputEvents(bool ignore_input_events);

  void SetWindow(std::unique_ptr<ApplicationWindowHost> window);
  void DestroyWindow();

  // substitute for BrowserContext::GetConnectorFor()
  service_manager::Connector* GetConnector();

  RendererAudioOutputStreamFactoryContext* GetRendererAudioOutputStreamFactoryContext();

  resource_coordinator::ProcessResourceCoordinator* GetProcessResourceCoordinator();

  scoped_refptr<net::URLRequestContextGetter> GetUrlRequestContextGetter();

  scoped_refptr<BackgroundFetchContext> GetBackgroundFetchContext();

  bool FastShutdownIfPossible(size_t page_count, bool skip_unload_handlers);

  // Binds Mojo request to Mojo implementation CacheStorageDispatcherHost
  // instance, binding is sent to IO thread.
  void BindCacheStorage(blink::mojom::CacheStorageRequest request,
                        const url::Origin& origin);

  // std::unique_ptr<NavigationLoaderInterceptor> CreateServiceWorkerInterceptor(
  //   const common::NavigationRequestInfo& request_info,
  //   ServiceWorkerNavigationHandleCore* service_worker_navigation_handle_core) const;

private:
  friend class IOThread;
  
  class ConnectionFilterController;
  class ConnectionFilterImpl;
 
  // mojom::RouteProvider:
  void GetRoute(
    int32_t routing_id,
    common::mojom::AssociatedInterfaceProviderAssociatedRequest request) override;

  // mojom::AssociatedInterfaceProvider:
  void GetAssociatedInterface(
    const std::string& name,
    common::mojom::AssociatedInterfaceAssociatedRequest request) override;

  // mojom::ApplicationHost
  void ShutdownRequest() override;

  void OnGpuSwitched() override;
  // void CreateOffscreenCanvasProvider(
  //     blink::mojom::OffscreenCanvasProviderRequest request);
  // NOTE: Commented because our current blink version
  //       doesnt have a EmbeddedFrameSinkProvider
  //       this is probably something from future versions

  //void CreateEmbeddedFrameSinkProvider(
  //     blink::mojom::EmbeddedFrameSinkProviderRequest request);
  void BindRouteProvider(common::mojom::RouteProviderAssociatedRequest request);
  void BindFrameSinkProvider(common::mojom::FrameSinkProviderRequest request);
  void BindCompositingModeReporter(
      viz::mojom::CompositingModeReporterRequest request);
  // Initializes a new IPC::ChannelProxy in |channel_|, which will be connected
  // to the next child process launched for this host, if any.
  void InitializeChannelProxy();
  // Resets |channel_|, removing it from the attachment broker if necessary.
  // Always call this in lieu of directly resetting |channel_|.
  void ResetChannelProxy();

  void CreateURLLoaderFactory(network::mojom::URLLoaderFactoryRequest request);
  
  // Creates and adds the IO thread message filters.
  void CreateMessageFilters();

  // Registers Mojo interfaces to be exposed to the renderer.
  void RegisterMojoInterfaces();
 
  void CreateApplicationHost(
     common::mojom::ApplicationHostAssociatedRequest request);

    // message handlers
  void OnShutdownRequest();
 
  // Handle termination of our process.
  void ProcessDied(bool already_dead, ChildProcessTerminationInfo* known_details);
  void ResetIPC();

  void ShutdownInternal();
  void OnChannelConnectedImpl(int32_t peer_pid);

  void CleanupOnIO();

  template <typename InterfaceType>
  using AddInterfaceCallback =
      base::Callback<void(mojo::InterfaceRequest<InterfaceType>)>;

  template <typename CallbackType>
  struct InterfaceGetter;

  template <typename InterfaceType>
   struct InterfaceGetter<AddInterfaceCallback<InterfaceType>> {
    static void GetInterfaceOnUIThread(
        base::WeakPtr<ApplicationProcessHost> weak_host,
        const AddInterfaceCallback<InterfaceType>& callback,
        mojo::InterfaceRequest<InterfaceType> request) {
      if (!weak_host)
        return;
      callback.Run(std::move(request));
    }
  };

  template <typename CallbackType>
   void AddUIThreadInterface(service_manager::BinderRegistry* registry,
                            const CallbackType& callback) {
    registry->AddInterface(
        base::Bind(&InterfaceGetter<CallbackType>::GetInterfaceOnUIThread,
                   //instance_weak_factory_->GetWeakPtr(), callback),
                   weak_factory_.GetWeakPtr(), callback),
        HostThread::GetTaskRunnerForThread(HostThread::UI));
   }

  static void OnMojoError(int id, const std::string& error);

  void DispatchMessageForListenersOnUI(const IPC::Message& message);

  void RecomputeAndUpdateWebKitPreferences();
  void NotifyApplicationProcessExited(const ChildProcessTerminationInfo& info);

  void BuildNetworkContext();
  void BuildNetworkContextOnIO(
    std::unique_ptr<HostNetworkDelegate> host_network_delegate,
    std::unique_ptr<net::HostResolver> host_resolver,
    std::unique_ptr<net::CertVerifier> cert_verifier,
    std::unique_ptr<net::MultiLogCTVerifier> ct_verifier);

  base::WeakPtr<Application> application_;
  std::string application_name_;
  base::FilePath application_executable_;
  base::FilePath application_root_;
  base::UUID application_uuid_;
  GURL application_url_;

  Domain* domain_;
  scoped_refptr<ApplicationDriver> application_driver_;

  std::unique_ptr<mojo::edk::OutgoingBrokerClientInvitation> broker_client_invitation_;
 
  std::unique_ptr<common::ChildConnection> child_connection_;
  int connection_filter_id_ = common::ServiceManagerConnection::kInvalidConnectionFilterId;

  scoped_refptr<ConnectionFilterController> connection_filter_controller_;

  // Mojo interfaces provided to the child process are registered here if they
  // need consistent delivery ordering with legacy IPC, and are process-wide in
  // nature (e.g. metrics, memory usage).
  std::unique_ptr<common::AssociatedInterfaceRegistryImpl> associated_interfaces_;

  mojo::AssociatedBinding<common::mojom::RouteProvider> route_provider_binding_;
  mojo::AssociatedBindingSet<common::mojom::AssociatedInterfaceProvider, int32_t>
    associated_interface_provider_bindings_;

  ChildProcessLauncherPriority priority_;

  //std::unique_ptr<OffscreenCanvasProviderImpl> offscreen_canvas_provider_;
  
  common::mojom::ChildControlPtr child_control_interface_;
  common::mojom::RouteProviderAssociatedPtr remote_route_provider_;
  common::mojom::ApplicationAssociatedPtr application_interface_;
  network::mojom::NetworkContextPtr network_context_ptr_;
  std::unique_ptr<HostNetworkContext> network_context_;
  mojo::AssociatedBinding<common::mojom::ApplicationHost> application_host_binding_;
  //std::unique_ptr<ApplicationWindowHost, HostThread::DeleteOnIOThread> application_window_host_;
  std::unique_ptr<ApplicationWindowHost> application_window_host_;
  scoped_refptr<CacheStorageDispatcherHost> cache_storage_dispatcher_host_;
   // The filter for Web Notification messages coming from the renderer. Holds a
  // closure per notification that must be freed when the notification closes.
  scoped_refptr<NotificationMessageFilter> notification_message_filter_;

  // A proxy for our IPC::Channel that lives on the IO thread (see
  // host_process.h)
  std::unique_ptr<IPC::ChannelProxy> channel_;
  
  std::unique_ptr<ChildProcessLauncher> child_process_launcher_;  

  std::set<ApplicationWindowHost*> windows_;

  base::ObserverList<ApplicationProcessHostObserver> observers_;

  // True if the process can be shut down suddenly.  If this is true, then we're
  // sure that all the RenderViews in the process can be shutdown suddenly.  If
  // it's false, then specific RenderViews might still be allowed to be shutdown
  // suddenly by checking their SuddenTerminationAllowed() flag.  This can occur
  // if one WebContents has an unload event listener but another WebContents in
  // the same process doesn't.
  bool sudden_termination_allowed_;

  // Set to true if we shouldn't send input events.  We actually do the
  // filtering for this at the render widget level.
  bool ignore_input_events_;

  int id_;

  int instance_id_ = 1;

  bool is_shutting_down_;

  bool is_dead_;

  bool is_initialized_;
 
  bool channel_connected_;

  bool gpu_observer_registered_;

  bool headless_;

  int media_stream_count_;

  base::TimeTicks init_time_;

  base::AtomicSequenceNumber next_routing_id_;

  base::IDMap<IPC::Listener *> listeners_;

  std::unique_ptr<GpuClient, HostThread::DeleteOnIOThread> gpu_client_;
  
  std::unique_ptr<FrameSinkProviderImpl> frame_sink_provider_;
  //std::unique_ptr<EmbeddedFrameSinkProviderImpl> embedded_frame_sink_provider_;
  std::unique_ptr<mojo::Binding<viz::mojom::CompositingModeReporter>>
      compositing_mode_reporter_;

  std::unique_ptr<resource_coordinator::ProcessResourceCoordinator>
      process_resource_coordinator_;

  scoped_refptr<ApplicationWindowHelper> window_helper_;

  std::unique_ptr<RendererAudioOutputStreamFactoryContextImpl, HostThread::DeleteOnIOThread>
      audio_output_stream_factory_context_;

  scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner_;

  scoped_refptr<P2PSocketDispatcherHost> p2p_socket_dispatcher_host_;

  // Forwards messages between WebRTCInternals in the browser process
  // and PeerConnectionTracker in the renderer process.
  // It holds a raw pointer to webrtc_eventlog_host_, and therefore should be
  // defined below it so it is destructed first.
  scoped_refptr<PeerConnectionTrackerHost> peer_connection_tracker_host_;

  scoped_refptr<ResourceMessageFilter> resource_message_filter_;
  
  base::WeakPtrFactory<ApplicationProcessHost> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationProcessHost);
};  

}

#endif
