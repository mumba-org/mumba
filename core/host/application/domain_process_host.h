// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_PROCESS_HOST_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_PROCESS_HOST_H_

#include <map>
#include <string>

#include "base/macros.h"
#include "base/callback.h"
#include "base/atomic_sequence_num.h"
#include <memory>
#include "base/containers/id_map.h"
#include "base/observer_list.h"
#include "base/macros.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_listener.h"
#include "ipc/ipc_channel_proxy.h"
#include "core/common/common_data.h"
#include "core/common/request_codes.h"
#include "core/common/process_launcher_delegate.h"
#include "core/shared/common/associated_interface_registry_impl.h"
#include "core/shared/common/associated_interfaces.mojom.h"
#include "core/shared/common/child_control.mojom.h"
#include "core/shared/common/mojom/domain.mojom.h"
#include "core/shared/common/mojom/device.mojom.h"
#include "core/shared/common/mojom/window.mojom.h"
#include "core/shared/common/mojom/module.mojom.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "core/shared/common/mojom/launcher.mojom.h"
#include "core/shared/common/mojom/identity.mojom.h"
#include "core/shared/common/mojom/storage.mojom.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/associated_interface_registry_impl.h"
#include "core/shared/common/associated_interfaces.mojom.h"
#include "core/shared/common/bind_interface_helpers.h"
#include "core/host/application/frame_sink_provider_impl.h"
#include "core/host/child_process_launcher.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "mojo/edk/embedder/outgoing_broker_client_invitation.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/mojom/service.mojom.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/mojom/service.mojom.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "services/viz/public/interfaces/compositing/compositing_mode_watcher.mojom.h"
#include "core/host/application/offscreen_canvas_provider_impl.h"
#include "core/host/cache_storage/cache_storage_dispatcher_host.h"
#include "components/viz/client/frame_evictor.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/host/host_frame_sink_client.h"
#include "core/host/compositor/image_transport_factory.h"
#include "core/host/application/dip_util.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/shared/common/content_export.h"
#include "services/viz/public/interfaces/compositing/compositor_frame_sink.mojom.h"
#include "services/viz/public/interfaces/hit_test/hit_test_region_list.mojom.h"
#include "ui/compositor/compositor.h"
#include "ui/compositor/compositor_observer.h"
#include "ui/compositor/layer.h"
#include "ui/events/event.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gl/gpu_switching_observer.h"

namespace common {
class ChildConnection;
class ServiceManagerConnection;
}

namespace net {
class URLRequestContextGetter;  
class HostResolver;
class CertVerifier;
class MultiLogCTVerifier;
}

namespace resource_coordinator {
class ProcessResourceCoordinator;
}

namespace host {
class Domain;
class IOThread;
class MojoDomainPoolService;
class DeviceDispatcherHost;
class ModuleDispatcherHost;
class WindowManagerHost;
class StorageDispatcherHost;
class P2PSocketDispatcherHost;
class HostMessageFilter;
class StorageManager;
class ServiceDispatcherHost;
class IdentityManagerHost;
class LauncherHost;
class NotificationMessageFilter;
class HostNetworkContext;
class ResourceMessageFilter;
class HostNetworkDelegate;
class BackgroundFetchContext;
class PeerConnectionTrackerHost;
class OffscreenCanvasProviderImpl;
class CacheStorageDispatcherHost;
class GpuClient;

class DomainProcessHost : public IPC::Sender,
                           public IPC::Listener,
                           public common::mojom::RouteProvider,
                           public common::mojom::AssociatedInterfaceProvider,
                           public ChildProcessLauncher::Client,
                           public ui::GpuSwitchingObserver,
                           public common::mojom::DomainHost,
                           // FIXME: it should be decoupled from process host
                           public viz::mojom::CompositorFrameSink,
                           public viz::HostFrameSinkClient {
public:
 using iterator = base::IDMap<DomainProcessHost*>::iterator;
 
 static iterator AllHostsIterator();
 static DomainProcessHost* FromID(int32_t process_id);

 class Observer {
  public:
   virtual void DomainProcessReady(DomainProcessHost* host) {}
   virtual void DomainProcessShutdownRequested(DomainProcessHost* host) {}
   virtual void DomainProcessWillExit(DomainProcessHost* host) {}
   virtual void DomainProcessExited(DomainProcessHost* host,
                                   const ChildProcessTerminationInfo& info) {}
   virtual void DomainProcessHostDestroyed(DomainProcessHost* host) {}
  protected:
   virtual ~Observer() {}
 };

 DomainProcessHost(Domain* shell, 
                    StorageManager* storage_manager, 
                    const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner);
 ~DomainProcessHost() override;

 bool Init(const std::string& name, const base::UUID& id);
 void EnableSendQueue();
 int GetID() const;
 Domain* domain() const;
 const base::Process& GetProcess() const;
 IPC::ChannelProxy* GetChannelProxy();
 common::mojom::Domain* GetDomainInterface();
 common::mojom::ModuleDispatcher* GetModuleDispatcherInterface();
 common::mojom::DeviceManager* GetDeviceManagerInterface();
 common::mojom::WindowManagerClient* GetWindowManagerClientInterface();
 common::mojom::StorageDispatcher* GetStorageDispatcherInterface();
 common::mojom::LauncherClient* GetLauncherClientInterface();
 common::mojom::ServiceDispatcher* GetServiceDispatcherInterface();
 common::mojom::IdentityManagerClient* GetIdentityManagerClientInterface();
 service_manager::Connector* GetConnector() const;
 
 int GetNextRoutingID();

 bool HasConnection() const;
 bool IsReady() const;

 const service_manager::Identity& GetChildIdentity() const;
 service_manager::BinderRegistry* GetBinderRegistry() const;

 void AddObserver(Observer* observer);
 void RemoveObserver(Observer* observer);

 void AddRoute(int32_t routing_id, IPC::Listener* listener);
 void RemoveRoute(int32_t routing_id);

 void Cleanup();
 bool Shutdown(int exit_code, bool wait);

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

 static void RegisterHost(int host_id, DomainProcessHost* host);
 static void UnregisterHost(int host_id);

 base::WeakPtr<DomainProcessHost> GetWeakPtr() {
     DCHECK_CURRENTLY_ON(HostThread::UI);
     return ui_weak_factory_->GetWeakPtr();
 }

 base::WeakPtr<DomainProcessHost> GetWeakPtrForIO() {
     DCHECK_CURRENTLY_ON(HostThread::IO);
     return io_weak_factory_.GetWeakPtr();
 }

 NotificationMessageFilter* notification_message_filter() const {
  return notification_message_filter_.get();
 }

 scoped_refptr<net::URLRequestContextGetter> GetUrlRequestContextGetter();
 scoped_refptr<BackgroundFetchContext> GetBackgroundFetchContext();

 // Binds Mojo request to Mojo implementation CacheStorageDispatcherHost
 // instance, binding is sent to IO thread.
 void BindCacheStorageWithOrigin(const url::Origin& origin, blink::mojom::CacheStorageRequest request);
 void BindCacheStorage(blink::mojom::CacheStorageRequest request);
 void BindAssociatedCacheStorage(blink::mojom::CacheStorageAssociatedRequest request);

 //void CreateOffscreenCanvasProvider(blink::mojom::OffscreenCanvasProviderRequest request);

 HostNetworkContext* GetNetworkContext() const {
    return network_context_.get();
 }

 void CreateURLLoaderFactory(network::mojom::URLLoaderFactoryRequest request);

 resource_coordinator::ProcessResourceCoordinator* GetProcessResourceCoordinator();

 void OnGpuSwitched() override;
 void BindFrameSinkProvider(common::mojom::FrameSinkProviderRequest request);
 void BindCompositingModeReporter(
      viz::mojom::CompositingModeReporterRequest request);
 void RequestCompositorFrameSink(
    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client);

private:
  class ConnectionFilterController;
  class ConnectionFilterImpl;
  friend class Domain;
  
 // mojom::RouteProvider:
 void GetRoute(
    int32_t routing_id,
    common::mojom::AssociatedInterfaceProviderAssociatedRequest request) override;

 // mojom::AssociatedInterfaceProvider:
 void GetAssociatedInterface(
    const std::string& name,
    common::mojom::AssociatedInterfaceAssociatedRequest request) override;

 // mojom::DomainHost
 void ShutdownRequest() override;


 void BindRouteProvider(common::mojom::RouteProviderAssociatedRequest request);

 // Initializes a new IPC::ChannelProxy in |channel_|, which will be connected
 // to the next child process launched for this host, if any.
 void InitializeChannelProxy();
 // Resets |channel_|, removing it from the attachment broker if necessary.
 // Always call this in lieu of directly resetting |channel_|.
 void ResetChannelProxy();

 // Creates and adds the IO thread message filters.
 void CreateMessageFilters();

 // Registers Mojo interfaces to be exposed to the renderer.
 void RegisterMojoInterfaces();
 
 void CreateDomainHost(
    common::mojom::DomainHostAssociatedRequest request);

 // message handlers
 void OnShutdownRequest();
 
 // Handle termination of our process.
 void ProcessDied(bool already_dead, ChildProcessTerminationInfo* known_details);
 void ResetIPC();

 void ShutdownInternal();

 void OnChannelConnectedImpl(int32_t peer_pid);

 template <typename InterfaceType>
  using AddInterfaceCallback =
      base::Callback<void(mojo::InterfaceRequest<InterfaceType>)>;

 template <typename CallbackType>
 struct InterfaceGetter;

 template <typename InterfaceType>
  struct InterfaceGetter<AddInterfaceCallback<InterfaceType>> {
    static void GetInterfaceOnUIThread(
        base::WeakPtr<DomainProcessHost> weak_host,
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
                   instance_weak_factory_->GetWeakPtr(), callback),
        HostThread::GetTaskRunnerForThread(HostThread::UI));
  }

 static void OnMojoError(int id, const std::string& error);

 // viz::mojom::CompositorFrameSinkClient implementation.
 void SetNeedsBeginFrame(bool needs_begin_frame) override;
 void SetWantsAnimateOnlyBeginFrames() override;
 void SubmitCompositorFrame(const viz::LocalSurfaceId& local_surface_id, viz::CompositorFrame frame, ::viz::mojom::HitTestRegionListPtr hit_test_region_list, uint64_t submit_time) override;
 void DidNotProduceFrame(const viz::BeginFrameAck& ack) override;
 void DidAllocateSharedBitmap(mojo::ScopedSharedBufferHandle buffer, const gpu::Mailbox& id) override;
 void DidDeleteSharedBitmap(const gpu::Mailbox& id) override;

 // viz::HostFrameSinkClient implementation.
 void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override;
 void OnFrameTokenChanged(uint32_t frame_token) override;

 void NotifyDomainProcessExited(const ChildProcessTerminationInfo& info);

 void BuildNetworkContext();
 void BuildNetworkContextOnIO(
    std::unique_ptr<HostNetworkDelegate> host_network_delegate,
    std::unique_ptr<net::HostResolver> host_resolver,
    std::unique_ptr<net::CertVerifier> cert_verifier,
    std::unique_ptr<net::MultiLogCTVerifier> ct_verifier);

 //void CreateDomainPoolService(common::mojom::DomainPoolServiceRequest request);

 // keep a copy of channel id here, so we can check its id later
 //std::string channel_id_;

 //base::FilePath channel_path_;

 // parent shell
 Domain* domain_;

 std::unique_ptr<mojo::edk::OutgoingBrokerClientInvitation> broker_client_invitation_;
 
 std::unique_ptr<common::ChildConnection> child_connection_;
 int connection_filter_id_ = common::ServiceManagerConnection::kInvalidConnectionFilterId;

 scoped_refptr<ConnectionFilterController> connection_filter_controller_;
 service_manager::mojom::ServicePtr test_service_;

 // The registered IPC listener objects. When this list is empty, we should
 // delete ourselves.
 base::IDMap<IPC::Listener *> listeners_;

 // Mojo interfaces provided to the child process are registered here if they
 // need consistent delivery ordering with legacy IPC, and are process-wide in
 // nature (e.g. metrics, memory usage).
 std::unique_ptr<common::AssociatedInterfaceRegistryImpl> associated_interfaces_;

 mojo::AssociatedBinding<common::mojom::RouteProvider> route_provider_binding_;
 mojo::AssociatedBindingSet<common::mojom::AssociatedInterfaceProvider, int32_t>
  associated_interface_provider_bindings_;

 ChildProcessLauncherPriority priority_;

 common::mojom::ChildControlPtr child_control_interface_;
 common::mojom::RouteProviderAssociatedPtr remote_route_provider_;
 common::mojom::DomainAssociatedPtr domain_interface_;
 mojo::AssociatedBinding<common::mojom::DomainHost> domain_host_binding_;

 // A proxy for our IPC::Channel that lives on the IO thread (see
 // host_process.h)
 std::unique_ptr<IPC::ChannelProxy> channel_;
 
 std::unique_ptr<ChildProcessLauncher> child_process_launcher_;

 std::unique_ptr<DeviceDispatcherHost, HostThread::DeleteOnIOThread>
      device_dispatcher_host_;
 std::unique_ptr<ModuleDispatcherHost, HostThread::DeleteOnIOThread>
      module_dispatcher_host_;
 std::unique_ptr<WindowManagerHost, HostThread::DeleteOnIOThread>
      window_manager_host_;
 std::unique_ptr<StorageDispatcherHost, HostThread::DeleteOnIOThread>
      storage_dispatcher_host_;
 std::unique_ptr<ServiceDispatcherHost, HostThread::DeleteOnIOThread>
      service_dispatcher_host_;
 std::unique_ptr<IdentityManagerHost, HostThread::DeleteOnIOThread>
      identity_manager_host_;
 std::unique_ptr<LauncherHost, HostThread::DeleteOnIOThread>
      launcher_host_;                   

 //std::unique_ptr<MojoDomainPoolService> domain_service_;
 scoped_refptr<CacheStorageDispatcherHost> cache_storage_dispatcher_host_;
 scoped_refptr<P2PSocketDispatcherHost> p2p_socket_dispatcher_host_;
 // The filter for Web Notification messages coming from the service. Holds a
 // closure per notification that must be freed when the notification closes.
 scoped_refptr<NotificationMessageFilter> notification_message_filter_;
 network::mojom::NetworkContextPtr network_context_ptr_;
 std::unique_ptr<HostNetworkContext> network_context_;

 scoped_refptr<ResourceMessageFilter> resource_message_filter_;

 //std::unique_ptr<OffscreenCanvasProviderImpl> offscreen_canvas_provider_;

 scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner_;

 //base::ObserverList<Observer> observers_;

 std::vector<Observer*> observers_;
 base::Lock observers_lock_;

 int id_;

 int instance_id_ = 1;

 bool is_shutting_down_;

 bool is_dead_;

 bool is_initialized_;
 
 bool channel_connected_;

 bool gpu_observer_registered_;

 base::TimeTicks init_time_;

 base::AtomicSequenceNumber next_routing_id_;

 std::unique_ptr<resource_coordinator::ProcessResourceCoordinator> process_resource_coordinator_;
 std::unique_ptr<GpuClient, HostThread::DeleteOnIOThread> gpu_client_;
 std::unique_ptr<FrameSinkProviderImpl> frame_sink_provider_;
 std::unique_ptr<mojo::Binding<viz::mojom::CompositingModeReporter>> compositing_mode_reporter_;

 mojo::Binding<viz::mojom::CompositorFrameSink> compositor_frame_sink_binding_;
 viz::mojom::CompositorFrameSinkClientPtr service_compositor_frame_sink_;

 // Stash a request to create a CompositorFrameSink if it arrives before
 // we have a view. This is only used if |enable_viz_| is true.
 base::OnceCallback<void(const viz::FrameSinkId&)> create_frame_sink_callback_;

 viz::FrameSinkId frame_sink_id_;

 common::ServiceManagerConnection* service_manager_connection_;
 
 //Delegate* delegate_;
 std::unique_ptr<base::WeakPtrFactory<DomainProcessHost>> instance_weak_factory_;
 base::WeakPtrFactory<DomainProcessHost> io_weak_factory_;
 std::unique_ptr<base::WeakPtrFactory<DomainProcessHost>> ui_weak_factory_;

 DISALLOW_COPY_AND_ASSIGN(DomainProcessHost);
};

}

#endif