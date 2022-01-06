// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain_process_host.h"

#include "base/command_line.h"
#include "base/no_destructor.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/threading/thread_local.h"
#include "base/strings/string_number_conversions.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/child_process_messages.h"
#include "core/shared/common/connection_filter.h"
#include "core/shared/common/service_manager/child_connection.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "core/common/sandboxed_process_launcher_delegate.h"
#include "core/common/result_codes.h"
#include "core/shared/common/client.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/paths.h"
#include "core/shared/common/bind_interface_helpers.h"
#include "core/shared/common/child_process_host_impl.h"
#include "core/shared/common/in_process_child_thread_params.h"
#include "core/shared/common/service_manager/child_connection.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "core/shared/common/associated_interface_registry_impl.h"
#include "core/host/host_client.h"
#include "core/host/host.h"
#include "core/host/host_child_process_host_impl.h"
#include "core/host/host_message_filter.h"
#include "core/host/workspace/workspace.h"
#include "core/shared/common/mojom/constants.mojom.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/common/mojo_channel_switches.h"
#include "core/host/service_manager/service_manager_context.h"
#include "core/host/application/device_dispatcher_host.h"
#include "core/host/application/window_manager_host.h"
#include "core/host/application/module_dispatcher_host.h"
#include "core/host/application/service_dispatcher_host.h"
#include "core/host/application/launcher_host.h"
#include "core/host/application/identity_manager_host.h"
#include "core/host/application/storage_dispatcher_host.h"
#include "core/host/application/application_manager_host.h"
#include "core/host/application/domain_automation_host.h"
#include "core/host/application/resource_context.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/resource_message_filter.h"
#include "core/host/route/route_dispatcher_client.h"
#include "core/host/bundle/bundle.h"
#include "core/host/blob_storage/blob_dispatcher_host.h"
#include "core/host/fileapi/fileapi_message_filter.h"
#include "core/host/media/midi_host.h"
#include "core/host/background_fetch_delegate.h"
#include "core/host/background_fetch/background_fetch_delegate_factory.h"
#include "core/host/background_fetch/background_fetch_delegate_impl.h"
#include "core/host/background_sync/background_sync_controller_factory.h"
#include "core/host/background_sync/background_sync_controller_impl.h"
#include "core/host/cache_storage/cache_storage_context_impl.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/background_fetch/background_fetch_context.h"
#include "core/host/streams/stream_context.h"
#include "core/host/blob_storage/blob_registry_wrapper.h"
#include "core/host/blob_storage/chrome_blob_storage_context.h"
#include "core/host/fileapi/browser_file_system_helper.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host_main_loop.h"
#include "core/host/host_controller.h"
#include "core/host/gpu/gpu_client.h"
#include "core/host/net/host_network_delegate.h"
#include "core/host/net/host_network_context.h"
#include "core/host/cache_storage/cache_storage_context_impl.h"
#include "core/host/cache_storage/cache_storage_dispatcher_host.h"
#include "core/host/notifications/notification_message_filter.h"
#include "core/host/broadcast_channel/broadcast_channel_provider.h"
#include "core/host/service_worker/service_worker_dispatcher_host.h"
#include "core/host/background_fetch/background_fetch_context.h"
#include "core/host/child_process_security_policy_impl.h"
#include "core/host/channel/channel_manager.h"
#include "core/host/net/p2p/socket_dispatcher_host.h"
#include "core/host/host_controller.h"
#include "core/host/io_thread.h"
#include "core/host/route/route_registry.h"
#include "core/host/rpc/service_registry.h"
#include "net/url_request/url_request_context_getter.h"
#include "ipc/ipc.mojom.h"
#include "ipc/ipc_channel.h"
#include "ipc/ipc_channel_mojo.h"
#include "ipc/ipc_logging.h"
#include "services/device/public/mojom/battery_monitor.mojom.h"
#include "services/device/public/mojom/constants.mojom.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "services/resource_coordinator/public/cpp/process_resource_coordinator.h"
#include "services/resource_coordinator/public/cpp/resource_coordinator_features.h"
#include "services/service_manager/embedder/switches.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/runner/common/client_util.h"
#include "services/service_manager/runner/common/switches.h"
#include "services/service_manager/sandbox/switches.h"
#include "core/host/net/system_network_context_manager.h"
#include "core/host/network_service_instance.h"
#include "core/host/compositor/surface_utils.h"
#include "net/cert/caching_cert_verifier.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert_net/cert_net_fetcher_impl.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/http/http_auth_filter.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_auth_preferences.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_transaction_factory.h"
#include "net/net_buildflags.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/proxy_resolution/pac_file_fetcher_impl.h"
#include "net/proxy_resolution/proxy_config_service.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/chromium/quic_utils_chromium.h"
#include "net/socket/ssl_client_socket.h"
#include "net/url_request/url_fetcher.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/network/ignore_errors_cert_verifier.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/url_request_context_builder_mojo.h"
#include "url/url_constants.h"
#include "ui/gl/gpu_switching_manager.h"
#include "storage/storage_utils.h"

#if defined(OS_LINUX)
#include "core/common/zygote_handle.h"
#include "core/common/zygote_buildflags.h"
#endif

#if defined(OS_WIN)
#include "services/service_manager/sandbox/win/sandbox_win.h"
#endif

namespace host {

namespace {

// the global list of all shell processes
base::LazyInstance<base::IDMap<DomainProcessHost*>>::Leaky g_all_hosts =
    LAZY_INSTANCE_INITIALIZER;

// Command-line switches to propagate to the Domain process.
static const char* const kSwitchNames[] = {
    service_manager::switches::kDisableSeccompFilterSandbox,
    service_manager::switches::kNoSandbox,
};

class DomainSandboxedProcessLauncherDelegate
    : public common::SandboxedProcessLauncherDelegate {
 public:
  DomainSandboxedProcessLauncherDelegate() {}
  ~DomainSandboxedProcessLauncherDelegate() override {}
#if defined(OS_WIN)
  bool PreSpawnTarget(sandbox::TargetPolicy* policy) override {
    service_manager::SandboxWin::AddBaseHandleClosePolicy(policy);
    const base::string16& sid =
        common::GetClient()->host()->GetAppContainerSidForSandboxType(
            GetSandboxType());
    if (!sid.empty())
      service_manager::SandboxWin::AddAppContainerPolicy(policy, sid.c_str());
    return common::GetClient()->host()->PreSpawnDomain(policy);
  }
#endif  // OS_WIN
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  common::ZygoteHandle GetZygote() override {
    // const base::CommandLine& browser_command_line =
    //     *base::CommandLine::ForCurrentProcess();
    // base::CommandLine::StringType renderer_prefix =
    //     browser_command_line.GetSwitchValueNative(switches::kRendererCmdPrefix);
    // if (!renderer_prefix.empty())
    //   return nullptr;
    return common::GetGenericZygote();
  }
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)
  service_manager::SandboxType GetSandboxType() override {
    //return service_manager::SANDBOX_TYPE_SHELL;
    return service_manager::SANDBOX_TYPE_APPLICATION;
  }
};

//void PoolCb(common::mojom::DomainStatus status) {
  //LOG(INFO) << "load/unload module returned with code: " << ((status == common::mojom::DomainStatus::kOk) ? "ok" : "failed");
//}

const char kUserDataDir[] = "user-data-dir";

net::URLRequestContext* GetRequestContext(
    scoped_refptr<net::URLRequestContextGetter> request_context,
    scoped_refptr<net::URLRequestContextGetter> media_request_context,
    common::ResourceType resource_type) {
  // If the request has resource type of RESOURCE_TYPE_MEDIA, we use a request
  // context specific to media for handling it because these resources have
  // specific needs for caching.
  if (resource_type == common::RESOURCE_TYPE_MEDIA)
    return media_request_context->GetURLRequestContext();
  return request_context->GetURLRequestContext();
}

void GetContexts(
    ResourceContext* resource_context,
    scoped_refptr<net::URLRequestContextGetter> request_context,
    scoped_refptr<net::URLRequestContextGetter> media_request_context,
    common::ResourceType resource_type,
    ResourceContext** resource_context_out,
    net::URLRequestContext** request_context_out) {
  *resource_context_out = resource_context;
  *request_context_out =
      GetRequestContext(request_context, media_request_context, resource_type);
}

void CreateProcessResourceCoordinator(
    DomainProcessHost* domain_process_host,
    resource_coordinator::mojom::ProcessCoordinationUnitRequest request) {
  domain_process_host->GetProcessResourceCoordinator()->AddBinding(
      std::move(request));
}

}

class DomainProcessHost::ConnectionFilterController
    : public base::RefCountedThreadSafe<ConnectionFilterController> {
 public:
  // |filter| is not owned by this object.
  explicit ConnectionFilterController(ConnectionFilterImpl* filter)
      : filter_(filter) {}

  ConnectionFilterImpl* filter() const {
    return filter_;
  }

  void DisableFilter();

 private:
  friend class base::RefCountedThreadSafe<ConnectionFilterController>;
  friend class ConnectionFilterImpl;

  ~ConnectionFilterController() {}

  void Detach() {
    base::AutoLock lock(lock_);
    filter_ = nullptr;
  }

  base::Lock lock_;
  ConnectionFilterImpl* filter_;
};

class DomainProcessHost::ConnectionFilterImpl : public common::ConnectionFilter {
 public:
  ConnectionFilterImpl(
      const service_manager::Identity& child_identity,
      std::unique_ptr<service_manager::BinderRegistry> registry)
      : child_identity_(child_identity),
        registry_(std::move(registry)),
        controller_(new ConnectionFilterController(this)),
        weak_factory_(this) {
    // Registration of this filter may race with browser shutdown, in which case
    // it's possible for this filter to be destroyed on the main thread. This
    // is fine as long as the filter hasn't been used on the IO thread yet. We
    // detach the ThreadChecker initially and the first use of the filter will
    // bind it.
    thread_checker_.DetachFromThread();
  }

  ~ConnectionFilterImpl() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    controller_->Detach();
  }

  scoped_refptr<ConnectionFilterController> controller() { return controller_; }

  service_manager::BinderRegistry* registry() const {
    return registry_.get();
  }

  void Disable() {
    base::AutoLock lock(enabled_lock_);
    enabled_ = false;
  }

 private:
  // ConnectionFilter:
  void OnBindInterface(const service_manager::BindSourceInfo& source_info,
                       const std::string& interface_name,
                       mojo::ScopedMessagePipeHandle* interface_pipe,
                       service_manager::Connector* connector) override {
    DCHECK(thread_checker_.CalledOnValidThread());
    DCHECK_CURRENTLY_ON(HostThread::IO);
    // We only fulfill connections from the renderer we host.
    if (child_identity_.name() != source_info.identity.name() ||
        child_identity_.instance() != source_info.identity.instance()) {
      return;
    }

    base::AutoLock lock(enabled_lock_);
    if (!enabled_)
      return;

    registry_->TryBindInterface(interface_name, interface_pipe);
  }

  base::ThreadChecker thread_checker_;
  service_manager::Identity child_identity_;
  std::unique_ptr<service_manager::BinderRegistry> registry_;
  scoped_refptr<ConnectionFilterController> controller_;

  // Guards |enabled_|.
  base::Lock enabled_lock_;
  bool enabled_ = true;

  base::WeakPtrFactory<ConnectionFilterImpl> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ConnectionFilterImpl);
};

void DomainProcessHost::ConnectionFilterController::DisableFilter() {
  base::AutoLock lock(lock_);
  if (filter_)
    filter_->Disable();
}

// static
DomainProcessHost::iterator DomainProcessHost::AllHostsIterator() {
  //DCHECK_CURRENTLY_ON(HostThread::UI);
  //return iterator(g_all_hosts.Pointer());
  // TODO: see if we dont get in trouble for using this
  base::IDMap<DomainProcessHost*>& hosts = g_all_hosts.Get();
  return iterator(&hosts);
}

// static 
DomainProcessHost* DomainProcessHost::FromID(int32_t process_id) {
  DomainProcessHost* host = g_all_hosts.Get().Lookup(process_id);
  return host; 
}

DomainProcessHost::DomainProcessHost(
  Domain* shell, 
  StorageManager* storage_manager,
  const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner):
  domain_(shell),
  route_provider_binding_(this),
  priority_({
        true,//blink::kLaunchingProcessIsBackgrounded, 
        0,
        false//blink::kLaunchingProcessIsBoostedForPendingView
      }),
  domain_host_binding_(this),
  device_dispatcher_host_(new DeviceDispatcherHost()),
  module_dispatcher_host_(new ModuleDispatcherHost()),
  window_manager_host_(new WindowManagerHost()),
  storage_dispatcher_host_(new StorageDispatcherHost(storage_manager, shell)),
  service_dispatcher_host_(new ServiceDispatcherHost()),
  identity_manager_host_(new IdentityManagerHost()),
  launcher_host_(new LauncherHost()),
  id_(common::ChildProcessHostImpl::GenerateChildProcessUniqueId()),
  //available_(true),
  is_shutting_down_(false),
  is_dead_(true),
  is_initialized_(false),
  channel_connected_(false),
  gpu_observer_registered_(false),
  compositor_frame_sink_binding_(this),
  service_manager_connection_(nullptr),
  instance_weak_factory_(
          new base::WeakPtrFactory<DomainProcessHost>(this)),
  io_weak_factory_(this),
  ui_weak_factory_(new base::WeakPtrFactory<DomainProcessHost>(this)) {
    RegisterHost(GetID(), this); 
    auto controller = HostController::Instance();
    scoped_refptr<net::URLRequestContextGetter> request_context = controller->io_thread()->system_url_request_context_getter();
    p2p_socket_dispatcher_host_ = new P2PSocketDispatcherHost(domain_->workspace(), domain_, request_context.get(), acceptor_task_runner);
  
  gpu_client_.reset(new GpuClient(GetID()));
}

DomainProcessHost::~DomainProcessHost() {
  HostThread::GetTaskRunnerForThread(HostThread::UI)->DeleteSoon(FROM_HERE, frame_sink_provider_.release());
  HostThread::GetTaskRunnerForThread(HostThread::UI)->DeleteSoon(FROM_HERE, process_resource_coordinator_.release());

  loader_task_runner_ = nullptr;
  //DLOG(INFO) << "~DomainProcessHost";
  //ChildProcessSecurityPolicyImpl::GetInstance()->Remove(GetID());

  is_dead_ = true;

  //UnregisterHost(GetID());
}

int DomainProcessHost::GetNextRoutingID() {
  return next_routing_id_.GetNext() + 1;
}

Domain* DomainProcessHost::domain() const {
  return domain_;
}

service_manager::BinderRegistry* DomainProcessHost::GetBinderRegistry() const {
  return connection_filter_controller_->filter()->registry();
}

bool DomainProcessHost::Init(const std::string& name, const base::UUID& id) {
  const base::CommandLine& host_command_line =
      *base::CommandLine::ForCurrentProcess();

  const std::string& workspace_id = domain_->workspace()->name();

#if defined(OS_LINUX)
  int child_flags = common::ChildProcessHost::CHILD_ALLOW_SELF;
#else
  int child_flags = common::ChildProcessHost::CHILD_NORMAL;
#endif

  // Fixed for now
  base::FilePath command_path = common::ChildProcessHost::GetChildPath(child_flags);
  if (command_path.empty())
      return false;

  is_initialized_ = true;
  is_dead_ = false;

  if (!channel_)
    InitializeChannelProxy();

  channel_->Unpause(false /* flush */);

  // Call the embedder first so that their IPC filters have priority.
  service_manager::mojom::ServiceRequest service_request;
  common::GetClient()->host()->DomainProcessWillLaunch(this, &service_request);
  if (service_request.is_pending()) {
    GetDomainInterface()->CreateEmbedderDomainService(
        std::move(service_request));
  }

  frame_sink_provider_.reset(new FrameSinkProviderImpl(domain_, id_));

  // loader_task_runner_ = base::CreateSingleThreadTaskRunnerWithTraits(
  //   {base::MayBlock(), 
  //    //base::WithBaseSyncPrimitives(), 
  //    base::TaskPriority::USER_BLOCKING,
  //    base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
  //    base::SingleThreadTaskRunnerThreadMode::SHARED);

  // loader_task_runner_->PostTask(
  //   FROM_HERE,
  //   base::BindOnce(
  //     &DomainProcessHost::BuildNetworkContext,
  //     base::Unretained(this)));

  Bundle* bundle = domain()->bundle();
  DCHECK(bundle);

  gpu_client_->PreEstablishGpuChannel();
  
  loader_task_runner_ = HostThread::GetTaskRunnerForThread(HostThread::IO);
  BuildNetworkContext();

  CreateMessageFilters();

  RegisterMojoInterfaces();

  std::unique_ptr<base::CommandLine> cmd_line = std::make_unique<base::CommandLine>(command_path);
  cmd_line->AppendSwitchASCII(switches::kDomainProcess, "");
    
  cmd_line->AppendSwitchASCII(service_manager::switches::kServicePipeToken,
                                    child_connection_->service_token());
  cmd_line->AppendSwitchASCII(switches::kServiceRequestChannelToken,
                              child_connection_->service_token());
  
  cmd_line->AppendSwitchASCII(switches::kWorkspaceId, workspace_id);
  cmd_line->AppendSwitchASCII(switches::kDomainUUID, id.to_string());
  cmd_line->AppendSwitchASCII(switches::kDomainName, name);
  cmd_line->AppendSwitchASCII("bundle-path", bundle->executable_path());
  cmd_line->AppendSwitchASCII("domain-process-id", base::NumberToString(id_));
  
  cmd_line->CopySwitchesFrom(host_command_line, kSwitchNames,
                            arraysize(kSwitchNames));
  HostChildProcessHostImpl::CopyTraceStartupFlags(cmd_line.get());
  HostChildProcessHostImpl::CopyFeatureAndFieldTrialFlags(cmd_line.get());
  
  child_process_launcher_ = std::make_unique<ChildProcessLauncher>(
          std::make_unique<DomainSandboxedProcessLauncherDelegate>(),
          std::move(cmd_line), GetID(), this, std::move(broker_client_invitation_),
          base::BindRepeating(&DomainProcessHost::OnMojoError, id_),
          false, /*named pipe*/
          true /*terminate_on_shutdown*/);

  channel_->Pause();

  if (!gpu_observer_registered_) {
    gpu_observer_registered_ = true;
    ui::GpuSwitchingManager::GetInstance()->AddObserver(this);
  }

  init_time_ = base::TimeTicks::Now();
  return true;
}

void DomainProcessHost::InitializeChannelProxy() {
 
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner =
      HostThread::GetTaskRunnerForThread(HostThread::IO);

  // Acquire a Connector which will route connections to a new instance of the
  // renderer service.
  service_manager::Connector* connector =
       ServiceManagerContext::GetConnectorForIOThread();

  if (!connector) {
    // Note that some embedders (e.g. Android WebView) may not initialize a
    // Connector per ApplicationContents. In those cases we fall back to the
    // browser-wide Connector.
    if (!common::ServiceManagerConnection::GetForProcess()) {
      // Additionally, some test code may not initialize the process-wide
      // ServiceManagerConnection prior to this point. This class of test code
      // doesn't care about render processes, so we can initialize a dummy
      // connection.
      common::ServiceManagerConnection::SetForProcess(common::ServiceManagerConnection::Create(
          mojo::MakeRequest(&test_service_), io_task_runner));
    }
    connector = common::ServiceManagerConnection::GetForProcess()->GetConnector();
  }

  // Establish a ServiceManager connection for the new domain service instance.
  broker_client_invitation_ =
      std::make_unique<mojo::edk::OutgoingBrokerClientInvitation>();
  service_manager::Identity child_identity(
      common::mojom::kDomainServiceName,
      //ApplicationContents::GetServiceUserIdFor(GetApplicationContents()),
      service_manager::mojom::kRootUserID,
      base::StringPrintf("%d_%d", id_, instance_id_++));
  child_connection_.reset(new common::ChildConnection(child_identity,
                                              broker_client_invitation_.get(),
                                              connector, io_task_runner));

  // Send an interface request to bootstrap the IPC::Channel. Note that this
  // request will happily sit on the pipe until the process is launched and
  // connected to the ServiceManager. We take the other end immediately and
  // plug it into a new ChannelProxy.
  mojo::MessagePipe pipe;
  BindInterface(IPC::mojom::ChannelBootstrap::Name_, std::move(pipe.handle1));
  std::unique_ptr<IPC::ChannelFactory> channel_factory =
      IPC::ChannelMojo::CreateServerFactory(
          std::move(pipe.handle0), io_task_runner,
          base::ThreadTaskRunnerHandle::Get());

  // was content::BindInterface
  common::BindInterface(this, &child_control_interface_);

  ResetChannelProxy();

  if (!channel_)
    channel_.reset(new IPC::ChannelProxy(this, io_task_runner.get(),
                                         base::ThreadTaskRunnerHandle::Get()));
  channel_->Init(std::move(channel_factory), true /* create_pipe_now */);

  // Note that Channel send is effectively paused and unpaused at various points
  // during startup, and existing code relies on a fragile relative message
  // ordering resulting from some early messages being queued until process
  // launch while others are sent immediately. See https://goo.gl/REW75h for
  // details.
  //
  // We acquire a few associated interface proxies here -- before the channel is
  // paused -- to ensure that subsequent initialization messages on those
  // interfaces behave properly. Specifically, this avoids the risk of an
  // interface being requested while the Channel is paused, which could
  // effectively and undesirably block the transmission of a subsequent message
  // on that interface while the Channel is unpaused.
  //
  // See OnProcessLaunched() for some additional details of this somewhat
  // surprising behavior.
  channel_->GetRemoteAssociatedInterface(&remote_route_provider_);
  channel_->GetRemoteAssociatedInterface(&domain_interface_);

  // TODO: this may not be the right thing to do. CHECK

  channel_->GetRemoteAssociatedInterface(&device_dispatcher_host_->device_interface_);
  channel_->GetRemoteAssociatedInterface(&module_dispatcher_host_->module_dispatcher_interface_);
  channel_->GetRemoteAssociatedInterface(&window_manager_host_->window_manager_client_interface_);
  channel_->GetRemoteAssociatedInterface(&storage_dispatcher_host_->storage_dispatcher_interface_);
  channel_->GetRemoteAssociatedInterface(&service_dispatcher_host_->service_dispatcher_interface_);
  channel_->GetRemoteAssociatedInterface(&identity_manager_host_->identity_manager_client_interface_);
  channel_->GetRemoteAssociatedInterface(&launcher_host_->launcher_client_interface_);

  channel_->GetRemoteAssociatedInterface(&domain_->host_manager()->application_manager_client_interface_);
  
  // We start the Channel in a paused state. It will be briefly unpaused again
  // in Init() if applicable, before process launch is initiated.
  channel_->Pause();
}
 
void DomainProcessHost::ResetChannelProxy() {
  if (!channel_)
    return;

  channel_.reset();
  channel_connected_ = false;
}

common::mojom::Domain* DomainProcessHost::GetDomainInterface() {
  return domain_interface_.get();
}

common::mojom::ModuleDispatcher* DomainProcessHost::GetModuleDispatcherInterface() {
  return module_dispatcher_host_->GetModuleDispatcherInterface();
}

common::mojom::DeviceManager* DomainProcessHost::GetDeviceManagerInterface() {
  return device_dispatcher_host_->GetDeviceManagerInterface();
}

common::mojom::WindowManagerClient* DomainProcessHost::GetWindowManagerClientInterface() {
  return window_manager_host_->GetWindowManagerClientInterface();
}

common::mojom::StorageDispatcher* DomainProcessHost::GetStorageDispatcherInterface() {
  return storage_dispatcher_host_->GetStorageDispatcherInterface(); 
}

common::mojom::IdentityManagerClient* DomainProcessHost::GetIdentityManagerClientInterface() {
  return identity_manager_host_->GetIdentityManagerClientInterface(); 
}

common::mojom::LauncherClient* DomainProcessHost::GetLauncherClientInterface() {
  return launcher_host_->GetLauncherClientInterface(); 
}

//common::mojom::ChannelDispatcher* DomainProcessHost::GetChannelDispatcherInterface() {
//  return channel_dispatcher_host_->GetChannelDispatcherInterface();
//}

common::mojom::ServiceDispatcher* DomainProcessHost::GetServiceDispatcherInterface() {
  return service_dispatcher_host_->GetServiceDispatcherInterface();
}


void DomainProcessHost::AddFilter(HostMessageFilter* filter) {
  filter->RegisterAssociatedInterfaces(channel_.get());
  channel_->AddFilter(filter->GetFilter());
}

// common::mojom::MountManager* DomainProcessHost::GetMountManagerInterface() {
//   return mount_dispatcher_host_->GetMountManagerInterface();
// }

const service_manager::Identity& DomainProcessHost::GetChildIdentity()
    const {
  return child_connection_->child_identity();
}

void DomainProcessHost::CreateMessageFilters() {
 
  scoped_refptr<net::URLRequestContextGetter> request_context(
      domain_->GetURLRequestContext());
 
  ResourceContext* resource_context = domain_->GetResourceContext();

  scoped_refptr<net::URLRequestContextGetter> media_request_context(
      domain_->GetMediaURLRequestContext());

  ResourceMessageFilter::GetContextsCallback get_contexts_callback(base::Bind(
      &GetContexts, resource_context, request_context, media_request_context));

  // Several filters need the Blob storage context, so fetch it in advance.
  scoped_refptr<ChromeBlobStorageContext> blob_storage_context = domain_->GetBlobStorageContext();
      //ChromeBlobStorageContext::GetFor(domain_);

  resource_message_filter_ = new ResourceMessageFilter(
      GetID(), domain_->GetAppCacheService(),
      blob_storage_context.get(),
      domain_->GetFileSystemContext(),
      domain_->GetServiceWorkerContext().get(),
      domain_->GetPrefetchURLLoaderService(),
      std::move(get_contexts_callback),
      HostThread::GetTaskRunnerForThread(HostThread::IO));

  AddFilter(resource_message_filter_.get());

  AddFilter(p2p_socket_dispatcher_host_.get());

  scoped_refptr<ServiceWorkerDispatcherHost> service_worker_filter =
      new ServiceWorkerDispatcherHost(kPROCESS_TYPE_SERVICE, GetID(), resource_context);
  scoped_refptr<ServiceWorkerContextWrapper> service_worker_context = domain_->GetServiceWorkerContext();
  service_worker_filter->Init(service_worker_context.get());
  AddFilter(service_worker_filter.get());
  
}

void DomainProcessHost::RegisterMojoInterfaces() {
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  std::unique_ptr<service_manager::BinderRegistry> registry = std::make_unique<service_manager::BinderRegistry>();

  AddUIThreadInterface(
      registry.get(),
      base::Bind(&Domain::CreateOffscreenCanvasProvider,
                 base::Unretained(domain_)));

  AddUIThreadInterface(registry.get(),
                       base::Bind(&DomainProcessHost::BindFrameSinkProvider,
                                  base::Unretained(this)));

  AddUIThreadInterface(
      registry.get(),
      base::Bind(&DomainProcessHost::BindCompositingModeReporter,
                 base::Unretained(this)));

  if (resource_coordinator::IsResourceCoordinatorEnabled()) {
    AddUIThreadInterface(
        registry.get(),
        base::Bind(&CreateProcessResourceCoordinator, base::Unretained(this)));
  }

  
  // |gpu_client_| outlives the registry, because its destruction is posted to
  // IO thread from the destructor of |this|.
  registry->AddInterface(
      base::Bind(&GpuClient::Add, base::Unretained(gpu_client_.get())));
  

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ModuleDispatcherHost::AddBinding,
                 base::Unretained(module_dispatcher_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DeviceDispatcherHost::AddBinding,
                 base::Unretained(device_dispatcher_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&WindowManagerHost::AddBinding,
                 base::Unretained(window_manager_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&StorageDispatcherHost::AddBinding,
                 base::Unretained(storage_dispatcher_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ServiceDispatcherHost::AddBinding,
                 base::Unretained(service_dispatcher_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&IdentityManagerHost::AddBinding,
                 base::Unretained(identity_manager_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&LauncherHost::AddBinding,
                 base::Unretained(launcher_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ApplicationManagerHost::AddBinding,
                 base::Unretained(domain_->host_manager_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&RouteRegistry::AddBinding,
                 base::Unretained(workspace->route_registry())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ServiceRegistry::AddBinding,
                 base::Unretained(workspace->service_registry())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ChannelManager::AddBinding,
                 base::Unretained(workspace->channel_manager())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddPageBinding,
                  base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddAccessibilityBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddAnimationBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddApplicationCacheBinding,
                 base::Unretained(domain_->automation_host_.get())));
  
  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddCacheStorageBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddCSSBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddDatabaseBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddDeviceOrientationBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddDOMBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddDOMSnapshotBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddDOMStorageBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddEmulationBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddHeadlessBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddHostBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddIndexedDBBinding,
                 base::Unretained(domain_->automation_host_.get())));               
  
  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddInputBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddIOBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddLayerTreeBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddNetworkBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddOverlayBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddServiceWorkerBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddStorageBinding,
                 base::Unretained(domain_->automation_host_.get())));
  
  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddSystemInfoBinding,
                 base::Unretained(domain_->automation_host_.get())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&DomainAutomationHost::AddTetheringBinding,
                 base::Unretained(domain_->automation_host_.get())));

  // should be called at every application launch
  //domain_->automation_host_->BindClientInterfaces(channel_.get());

  associated_interfaces_.reset(new common::AssociatedInterfaceRegistryImpl());
  common::GetClient()->host()->ExposeInterfacesToDomain(
      registry.get(), associated_interfaces_.get(), this);
  
  blink::AssociatedInterfaceRegistry* associated_registry =
      associated_interfaces_.get();

  associated_registry->AddInterface(base::Bind(
      &DomainProcessHost::BindRouteProvider, base::Unretained(this)));

  associated_registry->AddInterface(base::Bind(
      &DomainProcessHost::CreateDomainHost, base::Unretained(this)));
  
  //if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    //AddUIThreadInterface(
    //    registry.get(),
    registry->AddInterface(
        base::Bind(&DomainProcessHost::CreateURLLoaderFactory,
                   base::Unretained(this)));
  //}

  // registry->AddInterface(
  //     base::Bind(&RouteDispatcherClient::Bind, 
  //                 base::Unretained(domain_->GetRouteDispatcherClient())));
  
  service_manager_connection_ =
      common::ServiceManagerConnection::GetForProcess();
      //ApplicationContents::GetServiceManagerConnectionFor(application_contents_);
  std::unique_ptr<ConnectionFilterImpl> connection_filter(
      new ConnectionFilterImpl(child_connection_->child_identity(),
                               std::move(registry)));
  connection_filter_controller_ = connection_filter->controller();
  connection_filter_id_ = service_manager_connection_->AddConnectionFilter(
      std::move(connection_filter));
}

void DomainProcessHost::BindRouteProvider(
    common::mojom::RouteProviderAssociatedRequest request) {
  if (route_provider_binding_.is_bound())
    return;
  route_provider_binding_.Bind(std::move(request));
}

service_manager::Connector* DomainProcessHost::GetConnector() const {
  //return service_manager_connection_->GetConnector();
  return ServiceManagerContext::GetConnectorForIOThread();
}

void DomainProcessHost::GetRoute(
    int32_t routing_id,
    common::mojom::AssociatedInterfaceProviderAssociatedRequest request) {
  DCHECK(request.is_pending());
  associated_interface_provider_bindings_.AddBinding(
      this, std::move(request), routing_id);
}

void DomainProcessHost::GetAssociatedInterface(
    const std::string& name,
    common::mojom::AssociatedInterfaceAssociatedRequest request) {
  int32_t routing_id =
      associated_interface_provider_bindings_.dispatch_context();
  IPC::Listener* listener = listeners_.Lookup(routing_id);
  if (listener)
    listener->OnAssociatedInterfaceRequest(name, request.PassHandle());
}

void DomainProcessHost::BindInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  child_connection_->BindInterface(interface_name, std::move(interface_pipe));
}

void DomainProcessHost::CreateDomainHost(
    common::mojom::DomainHostAssociatedRequest request) {
  domain_host_binding_.Bind(std::move(request));
}

void DomainProcessHost::EnableSendQueue() {
  if (!channel_)
    InitializeChannelProxy();
}

void DomainProcessHost::AddObserver(DomainProcessHost::Observer* observer) {
  base::AutoLock lock(observers_lock_);
  observers_.push_back(observer);
}

void DomainProcessHost::RemoveObserver(DomainProcessHost::Observer* observer) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void DomainProcessHost::AddRoute(int32_t routing_id, IPC::Listener* listener) {
  listeners_.AddWithID(listener, routing_id);
}

void DomainProcessHost::RemoveRoute(int32_t routing_id) {
  listeners_.Remove(routing_id);
  Cleanup();
}

int DomainProcessHost::GetID() const {
  return id_;
}

bool DomainProcessHost::HasConnection() const {
  return channel_.get() != NULL;
}

void DomainProcessHost::Cleanup() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
//  if (listeners_.IsEmpty()) {
//   base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
//   channel_.reset();
//  }

  // Until there are no other owners of this object, we can't delete ourselves.
  // if (!listeners_.IsEmpty())
  //   return;

  // if (HasConnection() && child_process_launcher_.get()) {
  //   // Populates Android-only fields and closes the underlying base::Process.
  //   ChildProcessTerminationInfo info =
  //       child_process_launcher_->GetChildTerminationInfo(
  //           false /* already_dead */);
  //   info.status = base::TERMINATION_STATUS_NORMAL_TERMINATION;
  //   info.exit_code = 0;
  //   for (auto& observer : observers_) {
  //     observer.DomainProcessExited(this, info);
  //   }
  // }

  if (connection_filter_id_ !=
        common::ServiceManagerConnection::kInvalidConnectionFilterId) {
    common::ServiceManagerConnection* service_manager_connection =
        common::ServiceManagerConnection::GetForProcess();
        //ApplicationContents::GetServiceManagerConnectionFor(application_contents_);
    connection_filter_controller_->DisableFilter();
    service_manager_connection->RemoveConnectionFilter(connection_filter_id_);
    connection_filter_id_ =
        common::ServiceManagerConnection::kInvalidConnectionFilterId;
  }

  // Destroy all mojo bindings and IPC channels that can cause calls to this
  // object, to avoid method invocations that trigger usages of profile.
  //ResetIPC();

  //DCHECK(!channel_);

  //UnregisterHost(GetID());

  //base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
  
  //HostThread::DeleteSoon(HostThread::IO, FROM_HERE, this);

  ui_weak_factory_.reset();

  compositor_frame_sink_binding_.Close();

  //base::AutoLock lock(observers_lock_);
  for (auto* observer : observers_) {
    observer->DomainProcessHostDestroyed(this);
  }
}

IPC::ChannelProxy* DomainProcessHost::GetChannelProxy() {
  return channel_.get();
}

bool DomainProcessHost::Shutdown(int exit_code, bool wait) {
  GetDomainInterface()->Shutdown();
  return true;
}

void DomainProcessHost::OnProcessLaunched() {
  if (child_process_launcher_) {
    DCHECK(child_process_launcher_->GetProcess().IsValid());
    //DCHECK_EQ(blink::kLaunchingProcessIsBackgrounded, priority_.background);

    // Unpause the channel now that the process is launched. We don't flush it
    // yet to ensure that any initialization messages sent here (e.g., things
    // done in response to NOTIFICATION_RENDER_PROCESS_CREATED; see below)
    // preempt already queued messages.
    channel_->Unpause(false /* flush */);

    if (child_connection_) {
      child_connection_->SetProcessHandle(
          child_process_launcher_->GetProcess().Handle());
    }

    // Not all platforms launch processes in the same backgrounded state. Make
    // sure |priority_.background| reflects this platform's initial process
    // state.
#if defined(OS_MACOSX)
    priority_.background =
        child_process_launcher_->GetProcess().IsProcessBackgrounded(
            MachBroker::GetInstance());
#elif defined(OS_ANDROID)
    // Android child process priority works differently and cannot be queried
    // directly from base::Process.
    DCHECK_EQ(blink::kLaunchingProcessIsBackgrounded, priority_.background);
#else
    priority_.background =
        child_process_launcher_->GetProcess().IsProcessBackgrounded();
#endif  // defined(OS_MACOSX)
  }

  if (child_process_launcher_)
    channel_->Flush();

  if (IsReady()) {
    base::AutoLock lock(observers_lock_);
    for (auto* observer : observers_)
      observer->DomainProcessReady(this);
  }
}

void DomainProcessHost::OnProcessLaunchFailed(int error_code) {
  ChildProcessTerminationInfo info;
  info.status = base::TERMINATION_STATUS_LAUNCH_FAILED;
  info.exit_code = error_code;
  ProcessDied(true, &info);
}

bool DomainProcessHost::Send(IPC::Message* msg) {
 std::unique_ptr<IPC::Message> message(msg);
 if (!channel_)
    return false;
    
 return channel_->Send(message.release());
}

bool DomainProcessHost::OnMessageReceived(const IPC::Message& msg) {
 if (msg.routing_id() == MSG_ROUTING_CONTROL) {
  // Dispatch control messages.
  IPC_BEGIN_MESSAGE_MAP(DomainProcessHost, msg)
   IPC_MESSAGE_HANDLER(ChildProcessHostMsg_ShutdownRequest, OnShutdownRequest)
  IPC_END_MESSAGE_MAP()

   return true;
 }

 IPC::Listener* listener = listeners_.Lookup(msg.routing_id());
 if (!listener) {
  if (msg.is_sync()) {
   // The listener has gone away, so we must respond or else the caller will
   // hang waiting for a reply.
   IPC::Message* reply = IPC::SyncMessage::GenerateReply(&msg);
   reply->set_reply_error();
   Send(reply);
  }
  return true;
 }
 return listener->OnMessageReceived(msg);
}

const base::Process& DomainProcessHost::GetProcess() const {
  if (!child_process_launcher_.get() || child_process_launcher_->IsStarting()) {
    static const base::NoDestructor<base::Process> null_process;
    return *null_process;
  }

  return child_process_launcher_->GetProcess();
}

bool DomainProcessHost::IsReady() const {
  // The process launch result (that sets GetHandle()) and the channel
  // connection (that sets channel_connected_) can happen in either order.
  return GetProcess().Handle() && channel_connected_;
}

void DomainProcessHost::OnChannelConnected(int32_t peer_pid) {
#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  child_control_interface_->SetIPCLoggingEnabled(
      IPC::Logging::GetInstance()->Enabled());
#endif
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&DomainProcessHost::OnChannelConnectedImpl, 
      ui_weak_factory_->GetWeakPtr(), 
      peer_pid));
}

void DomainProcessHost::OnChannelConnectedImpl(int32_t peer_pid) {
  channel_connected_ = true;
  if (IsReady()) {
    base::AutoLock lock(observers_lock_);
    for (auto* observer : observers_)
      observer->DomainProcessReady(this);
  }  
  //base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
  //  FROM_HERE, 
  //  base::BindOnce(&DomainProcessHost::LoadModuleInternal, 
  //    weak_factory_.GetWeakPtr()),
  //  base::TimeDelta::FromSeconds(10));
}

void DomainProcessHost::OnChannelError() {
 ProcessDied(true, nullptr);
}

void DomainProcessHost::OnBadMessageReceived(const IPC::Message& message) {
 LOG(ERROR) << "bad message " << message.type() << " terminating console.";
 Shutdown(common::RESULT_CODE_KILLED_BAD_MESSAGE, false);
}

// DEPRECATED
void DomainProcessHost::ShutdownInternal() {
  //LOG(ERROR) << "CALLING DEPRECATED DomainProcessHost::ShutdownInternal";
  OnShutdownRequest();
}

void DomainProcessHost::ShutdownRequest() {
  base::AutoLock lock(observers_lock_);
  
  for (auto* observer : observers_) {
    observer->DomainProcessShutdownRequested(this);
  }
  for (auto* observer : observers_) {
    observer->DomainProcessWillExit(this);
  }
  p2p_socket_dispatcher_host_->OnChannelClosing();
  child_control_interface_->ProcessShutdown();
}

// DEPRECATED
void DomainProcessHost::OnShutdownRequest() {
 //LOG(ERROR) << "CALLING DEPRECATED DomainProcessHost::OnShutdownRequest";
 is_shutting_down_ = true; 

//  if (!Send(new ChildProcessMsg_Shutdown())) {
//    DLOG(ERROR) << "sending shutdown message failed";
//  }

//  //if (!child_process_launcher_) {
//  //  DLOG(ERROR) << " child_process_launcher_ is NULL!!";
//  //}

//  ProcessDied(false, nullptr);

 //delegate_->OnDomainProcessShutdown(channel_id_);
}

// Handle termination of our process.
void DomainProcessHost::ProcessDied(bool already_dead, ChildProcessTerminationInfo* known_info) {
  // child_process_launcher_ can be NULL in single process mode or if fast
  // termination happened.
  ChildProcessTerminationInfo info;
  info.exit_code = 0;
  if (known_info) {
    info = *known_info;
  } else if (child_process_launcher_.get()) {
    info = child_process_launcher_->GetChildTerminationInfo(already_dead);
    if (already_dead && info.status == base::TERMINATION_STATUS_STILL_RUNNING) {
      // May be in case of IPC error, if it takes long time for renderer
      // to exit. Child process will be killed in any case during
      // child_process_launcher_.reset(). Make sure we will not broadcast
      // FrameHostMsg_RenderProcessGone with status
      // TERMINATION_STATUS_STILL_RUNNING, since this will break WebContentsImpl
      // logic.
      info.status = base::TERMINATION_STATUS_PROCESS_CRASHED;

// TODO(siggi): Remove this once https://crbug.com/806661 is resolved.
//#if defined(OS_WIN)
//      if (info.exit_code == WAIT_TIMEOUT && g_analyze_hung_renderer)
//        g_analyze_hung_renderer(child_process_launcher_->GetProcess());
//#endif
    }
  }

  //child_process_launcher_.reset();
  is_dead_ = true;
  // Make sure no IPCs or mojo calls from the old process get dispatched after
  // it has died.
  //ResetIPC();

  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(
      &DomainProcessHost::NotifyDomainProcessExited, 
      ui_weak_factory_->GetWeakPtr(),
      info));
 
  // for (auto& observer : observers_)
  //   observer.DomainProcessExited(this, info);
  

  // base::IDMap<IPC::Listener*>::iterator iter(&listeners_);
  // while (!iter.IsAtEnd()) {
  //   iter.GetCurrentValue()->OnMessageReceived(FrameHostMsg_RenderProcessGone(
  //       iter.GetCurrentKey(), static_cast<int>(info.status), info.exit_code));
  //   iter.Advance();
  // }

  EnableSendQueue();

  // It's possible that one of the calls out to the observers might have caused
  // this object to be no longer needed.
  // if (delayed_cleanup_needed_)
  //Cleanup();

  child_process_launcher_.reset();

  UnregisterHost(GetID());

  p2p_socket_dispatcher_host_->OnChannelClosing();
  p2p_socket_dispatcher_host_ = nullptr;

  io_weak_factory_.InvalidateWeakPtrs();

  HostThread::PostTask(
    HostThread::UI, 
     FROM_HERE, 
     base::BindOnce(
       &DomainProcessHost::Cleanup, 
       base::Unretained(this)));
}

void DomainProcessHost::NotifyDomainProcessExited(const ChildProcessTerminationInfo& info) {
  //base::AutoLock lock(observers_lock_);
  for (auto* observer : observers_) {
    observer->DomainProcessExited(this, info);
  }
}

void DomainProcessHost::ResetIPC() {
  if (domain_host_binding_.is_bound())
    domain_host_binding_.Unbind();
  if (route_provider_binding_.is_bound())
    route_provider_binding_.Close();
  associated_interface_provider_bindings_.CloseAllBindings();
  associated_interfaces_.reset();

  // It's important not to wait for the DeleteTask to delete the channel
  // proxy. Kill it off now. That way, in case the profile is going away, the
  // rest of the objects attached to this RenderProcessHost start going
  // away first, since deleting the channel proxy will post a
  // OnChannelClosed() to IPC::ChannelProxy::Context on the IO thread.
  ResetChannelProxy();
}

void DomainProcessHost::OnMojoError(int id,
                                       const std::string& error) {
  LOG(ERROR) << "Terminating shell process for bad Mojo message: " << error;
}

// static 
void DomainProcessHost::RegisterHost(int host_id, DomainProcessHost* host) {
  g_all_hosts.Get().AddWithID(host, host_id);
}

// static 
void DomainProcessHost::UnregisterHost(int host_id) {
  DomainProcessHost* host = g_all_hosts.Get().Lookup(host_id);
  if (!host)
    return;

  g_all_hosts.Get().Remove(host_id);
}

// just test
// void DomainProcessHost::LoadModuleInternal() {
//   //GetPoolManagerInterface()->CreatePool("root", base::BindOnce(&PoolCb));
//   GetExecutionInterface()->LoadModule("code://module/hello", "", base::BindOnce(&PoolCb));
//   base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
//     FROM_HERE, 
//     base::BindOnce(&DomainProcessHost::UnloadModuleInternal, 
//       base::Unretained(this)),
//     base::TimeDelta::FromSeconds(60 * 2));
// }

// void DomainProcessHost::UnloadModuleInternal() {
//   //GetPoolManagerInterface()->CreatePool("root", base::BindOnce(&PoolCb));
//   GetExecutionInterface()->UnloadModule("hello", base::BindOnce(&PoolCb));
// }

scoped_refptr<net::URLRequestContextGetter> DomainProcessHost::GetUrlRequestContextGetter() {
  return domain_->GetURLRequestContext();
}

scoped_refptr<BackgroundFetchContext> DomainProcessHost::GetBackgroundFetchContext() {
  return nullptr;
}

// void DomainProcessHost::CreateOffscreenCanvasProvider(
//     blink::mojom::OffscreenCanvasProviderRequest request) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   if (!offscreen_canvas_provider_) {
//     // The client id gets converted to a uint32_t in FrameSinkId.
//     uint32_t domain_client_id = base::checked_cast<uint32_t>(id_);
//     offscreen_canvas_provider_ = std::make_unique<OffscreenCanvasProviderImpl>(
//         GetHostFrameSinkManager(), domain_client_id);
//   }
//   offscreen_canvas_provider_->Add(std::move(request));
// }

void DomainProcessHost::BindCacheStorage(blink::mojom::CacheStorageRequest request) {
  url::Origin origin = url::Origin::Create(GURL(domain_->name() + "://"));
  BindCacheStorageWithOrigin(origin, std::move(request));
}

void DomainProcessHost::BindCacheStorageWithOrigin(
  const url::Origin& origin,
  blink::mojom::CacheStorageRequest request) {
  //DCHECK_CURRENTLY_ON(HostThread::UI);

  if (!cache_storage_dispatcher_host_) {
    cache_storage_dispatcher_host_ =
        base::MakeRefCounted<CacheStorageDispatcherHost>();
    cache_storage_dispatcher_host_->Init(domain_->GetCacheStorageContext());
  }
  // Send the binding to IO thread, because Cache Storage handles Mojo IPC on IO
  // thread entirely.
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    cache_storage_dispatcher_host_->AddBinding(std::move(request), origin);
  } else {
    HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&CacheStorageDispatcherHost::AddBinding,
                     cache_storage_dispatcher_host_, std::move(request),
                     origin));
  }
}


void DomainProcessHost::BindAssociatedCacheStorage(blink::mojom::CacheStorageAssociatedRequest request) {
  url::Origin origin = url::Origin::Create(GURL(domain_->name() + "://"));
  if (!cache_storage_dispatcher_host_) {
    cache_storage_dispatcher_host_ =
        base::MakeRefCounted<CacheStorageDispatcherHost>();
    cache_storage_dispatcher_host_->Init(domain_->GetCacheStorageContext());
  }
  // Send the binding to IO thread, because Cache Storage handles Mojo IPC on IO
  // thread entirely.
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    cache_storage_dispatcher_host_->AddAssociatedBinding(std::move(request), origin);
  } else {
    HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&CacheStorageDispatcherHost::AddAssociatedBinding,
                     cache_storage_dispatcher_host_, std::move(request),
                     origin));
  }
}

void DomainProcessHost::BuildNetworkContext() {
  DCHECK(loader_task_runner_->RunsTasksInCurrentSequence());
  IOThread* io_thread = HostController::Instance()->io_thread();

  std::unique_ptr<HostNetworkDelegate> host_network_delegate = std::make_unique<HostNetworkDelegate>();
  std::unique_ptr<net::HostResolver> host_resolver = io_thread->CreateHostResolver();
  std::unique_ptr<net::CertVerifier> cert_verifier = 
    std::make_unique<net::CachingCertVerifier>(
       std::make_unique<net::MultiThreadedCertVerifier>(
           net::CertVerifyProc::CreateDefault()));
  std::unique_ptr<net::MultiLogCTVerifier> ct_verifier =
       std::make_unique<net::MultiLogCTVerifier>();
  
  // HostThread::PostTask(
  //   HostThread::IO, 
  //   FROM_HERE, 
  //   base::BindOnce(&ApplicationProcessHost::BuildNetworkContextOnIO,
  //    base::Unretained(this),
  //    base::Passed(std::move(host_network_delegate)),
  //    base::Passed(std::move(host_resolver)),
  //    base::Passed(std::move(cert_verifier)),
  //    base::Passed(std::move(ct_verifier))));
  BuildNetworkContextOnIO(
    std::move(host_network_delegate),
    std::move(host_resolver),
    std::move(cert_verifier),
    std::move(ct_verifier));
}

void DomainProcessHost::BuildNetworkContextOnIO(
  std::unique_ptr<HostNetworkDelegate> host_network_delegate,
  std::unique_ptr<net::HostResolver> host_resolver,
  std::unique_ptr<net::CertVerifier> cert_verifier,
  std::unique_ptr<net::MultiLogCTVerifier> ct_verifier) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  
  IOThread* io_thread = HostController::Instance()->io_thread();
  
  const base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
 
  std::unique_ptr<network::URLRequestContextBuilderMojo> builder =
       std::make_unique<network::URLRequestContextBuilderMojo>();
  builder->set_network_delegate(std::move(host_network_delegate));
  builder->set_ssl_config_service(io_thread->GetSSLConfigService());
  builder->SetHttpAuthHandlerFactory(io_thread->CreateDefaultAuthHandlerFactory(host_resolver.get()));
  builder->set_host_resolver(std::move(host_resolver));
  builder->SetCertVerifier(
       network::IgnoreErrorsCertVerifier::MaybeWrapCertVerifier(
           command_line, kUserDataDir, std::move(cert_verifier)));
  builder->set_ct_verifier(std::move(ct_verifier));
  builder->set_pac_quick_check_enabled(true);
  builder->set_pac_sanitize_url_policy(net::ProxyResolutionService::SanitizeUrlPolicy::UNSAFE);

  network::mojom::NetworkContextParamsPtr params = network::mojom::NetworkContextParams::New();
  params->context_name = domain_->name();
  params->http_cache_enabled = true;
  params->http_cache_path = domain_->partition_path().AppendASCII("cache");
  params->enable_data_url_support = true;
  params->enable_file_url_support = true;
  params->enable_ftp_url_support = true;

  network_context_ = std::make_unique<HostNetworkContext>(
        GetNetworkServiceImpl(), 
        mojo::MakeRequest(&network_context_ptr_),
        std::move(params), 
        std::move(builder));
}

void DomainProcessHost::CreateURLLoaderFactory(
    network::mojom::URLLoaderFactoryRequest request) {
  // if (!base::FeatureList::IsEnabled(network::features::kNetworkService)) {
  //   NOTREACHED();
  //   return;
  // }
  //GetNetworkContext()->CreateURLLoaderFactory(
  //    std::move(request), id_);

  // FIXME: this is happening on IO thread so we are risking
  //        problems here by accessing the global workspace handle
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  RouteRegistry* registry = workspace->route_registry();
  const std::vector<HostRpcService*>& services = domain_->services();
  DCHECK(services.size());
  HostRpcService* service = services[0];
  //DCHECK(service);
  std::unique_ptr<net::RpcMessageEncoder> encoder = service->BuildEncoder();

  GetNetworkContext()->CreateRpcURLLoaderFactory(
      loader_task_runner_,
      registry,
      std::move(encoder),   
      id_, // routing_id
      id_, // process_id
      std::move(request));    
}

void DomainProcessHost::OnGpuSwitched() {
  //RecomputeAndUpdateWebKitPreferences();
}

void DomainProcessHost::BindFrameSinkProvider(common::mojom::FrameSinkProviderRequest request) {
  frame_sink_provider_->Bind(std::move(request));
}

void DomainProcessHost::BindCompositingModeReporter(
    viz::mojom::CompositingModeReporterRequest request) {
  HostMainLoop::GetInstance()->GetCompositingModeReporter(
      std::move(request));
}

resource_coordinator::ProcessResourceCoordinator*
DomainProcessHost::GetProcessResourceCoordinator() {
  if (process_resource_coordinator_)
    return process_resource_coordinator_.get();

  if (!resource_coordinator::IsResourceCoordinatorEnabled()) {
    process_resource_coordinator_ =
        std::make_unique<resource_coordinator::ProcessResourceCoordinator>(
            nullptr);
  } else {
    auto* connection = common::ServiceManagerConnection::GetForProcess();
    process_resource_coordinator_ =
        std::make_unique<resource_coordinator::ProcessResourceCoordinator>(
            connection ? connection->GetConnector() : nullptr);
  }
  return process_resource_coordinator_.get();
}

void DomainProcessHost::SetNeedsBeginFrame(bool needs_begin_frame) {

}

void DomainProcessHost::SetWantsAnimateOnlyBeginFrames() {

}

void DomainProcessHost::SubmitCompositorFrame(const viz::LocalSurfaceId& local_surface_id, viz::CompositorFrame frame, ::viz::mojom::HitTestRegionListPtr hit_test_region_list, uint64_t submit_time) {

}

void DomainProcessHost::DidNotProduceFrame(const viz::BeginFrameAck& ack) {

}

void DomainProcessHost::DidAllocateSharedBitmap(mojo::ScopedSharedBufferHandle buffer, const gpu::Mailbox& id) {

}

void DomainProcessHost::DidDeleteSharedBitmap(const gpu::Mailbox& id) {

}

void DomainProcessHost::OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) {}
void DomainProcessHost::OnFrameTokenChanged(uint32_t frame_token) {}

void DomainProcessHost::RequestCompositorFrameSink(
    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client) {
  // if (enable_viz_) {
  //     // Connects the viz process end of CompositorFrameSink message pipes. The
  //     // renderer compositor may request a new CompositorFrameSink on context
  //     // loss, which will destroy the existing CompositorFrameSink.
  //     auto callback = base::BindOnce(
  //         [](viz::HostFrameSinkManager* manager,
  //            viz::mojom::CompositorFrameSinkRequest request,
  //            viz::mojom::CompositorFrameSinkClientPtr client,
  //            const viz::FrameSinkId& frame_sink_id) {
  //           manager->CreateCompositorFrameSink(
  //               frame_sink_id, std::move(request), std::move(client));
  //         },
  //         base::Unretained(GetHostFrameSinkManager()),
  //         std::move(compositor_frame_sink_request),
  //         std::move(compositor_frame_sink_client));

  //     // if (view_) {
  //     //   std::move(callback).Run(view_->GetFrameSinkId());
  //     // }
  //     // else {
  //     //   create_frame_sink_callback_ = std::move(callback);
  //     // }
  //     std::move(callback).Run(frame_sink_id_);

  //     return;
  // }

  if (compositor_frame_sink_binding_.is_bound()) {
    compositor_frame_sink_binding_.Close();
  }
  compositor_frame_sink_binding_.Bind(
      std::move(compositor_frame_sink_request),
      HostMainLoop::GetInstance()->GetResizeTaskRunner());
  service_compositor_frame_sink_ = std::move(compositor_frame_sink_client);
}

}
