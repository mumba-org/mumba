// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_process_host.h"

#include "base/command_line.h"
#include "base/no_destructor.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread.h"
#include "base/path_service.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/threading/thread_local.h"
#include "base/strings/string_number_conversions.h"
#include "core/shared/common/paths.h"
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
#include "core/host/host_main_loop.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
#include "core/host/network_service_instance.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/runnable.h"
#include "core/host/application/application.h"
#include "core/host/application/automation/application_driver.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_factory.h"
#include "core/host/application/application_process_host_observer.h"
#include "core/host/application/application_window_helper.h"
#include "core/host/application/media/peer_connection_tracker_host.h"
#include "core/host/notifications/notification_message_filter.h"
#include "core/host/broadcast_channel/broadcast_channel_provider.h"
#include "core/host/service_worker/service_worker_dispatcher_host.h"
#include "core/host/background_fetch/background_fetch_context.h"
#include "core/host/route/route_registry.h"
#include "core/host/channel/channel_manager.h"
#include "core/host/application/media/renderer_audio_output_stream_factory_context_impl.h"
#include "core/host/net/p2p/socket_dispatcher_host.h"
#include "core/shared/common/mojom/constants.mojom.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/common/mojo_channel_switches.h"
#include "core/host/service_manager/service_manager_context.h"
#include "core/host/application/window_manager_host.h"
#include "core/host/child_process_security_policy_impl.h"
#include "core/host/compositor/surface_utils.h"
#include "core/host/net/p2p/socket_dispatcher_host.h"
#include "core/host/host_controller.h"
#include "core/host/io_thread.h"
#include "core/host/gpu/gpu_client.h"
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
#include "core/host/application/resource_context.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/resource_message_filter.h"
#include "core/host/blob_storage/blob_dispatcher_host.h"
#include "core/host/fileapi/fileapi_message_filter.h"
#include "core/host/media/midi_host.h"
#include "core/host/background_fetch_delegate.h"
#include "core/host/background_fetch/background_fetch_delegate_factory.h"
#include "core/host/background_fetch/background_fetch_delegate_impl.h"
#include "core/host/background_sync/background_sync_controller_factory.h"
#include "core/host/background_sync/background_sync_controller_impl.h"
#include "core/host/background_fetch/background_fetch_service_impl.h"
#include "core/host/cache_storage/cache_storage_context_impl.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/background_fetch/background_fetch_context.h"
#include "core/host/streams/stream_context.h"
#include "core/host/blob_storage/blob_registry_wrapper.h"
#include "core/host/blob_storage/chrome_blob_storage_context.h"
#include "core/host/fileapi/browser_file_system_helper.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host_controller.h"
#include "core/host/net/host_network_delegate.h"
#include "core/host/net/host_network_context.h"
#include "core/host/cache_storage/cache_storage_context_impl.h"
#include "core/host/cache_storage/cache_storage_dispatcher_host.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/net/peer_manager.h"
#include "core/host/net/system_network_context_manager.h"
#include "core/host/network_service_instance.h"
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

// the global list of all application processes
//base::LazyInstance<base::IDMap<ApplicationProcessHost*>>::Leaky g_all_hosts =
//    LAZY_INSTANCE_INITIALIZER;

static const char* const kSwitchNames[] = {
  service_manager::switches::kNoSandbox,
};

const char kUserDataDir[] = "user-data-dir";

class ApplicationProcessHostIsReadyObserver : public ApplicationProcessHostObserver {
 public:
  ApplicationProcessHostIsReadyObserver(
    ApplicationProcessHost* application_process_host,
    base::OnceClosure task)
      : application_process_host_(application_process_host),
        task_(std::move(task)),
        weak_factory_(this) {
    application_process_host_->AddObserver(this);
    if (application_process_host_->IsReady())
      PostTask();
  }

  ~ApplicationProcessHostIsReadyObserver() override {
    application_process_host_->RemoveObserver(this);
  }

  void ApplicationProcessReady(ApplicationProcessHost* host) override { PostTask(); }

  void ApplicationProcessHostDestroyed(ApplicationProcessHost* host) override {
    delete this;
  }

 private:
  void PostTask() {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&ApplicationProcessHostIsReadyObserver::CallTask,
                       weak_factory_.GetWeakPtr()));
  }

  void CallTask() {
    DCHECK_CURRENTLY_ON(HostThread::UI);
    if (application_process_host_->IsReady())
      std::move(task_).Run();

    delete this;
  }

  ApplicationProcessHost* application_process_host_;
  base::OnceClosure task_;
  base::WeakPtrFactory<ApplicationProcessHostIsReadyObserver> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationProcessHostIsReadyObserver);
};


// the global list of all application processes
base::IDMap<ApplicationProcessHost*>& GetAllHosts() {
  static base::NoDestructor<base::IDMap<ApplicationProcessHost*>> s_all_hosts;
  return *s_all_hosts;
}

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

// void CreateMemoryCoordinatorHandle(
//     int render_process_id,
//     common::mojom::MemoryCoordinatorHandleRequest request) {
//   MemoryCoordinatorImpl::GetInstance()->CreateHandle(render_process_id,
//                                                      std::move(request));
// }

void CreateProcessResourceCoordinator(
    ApplicationProcessHost* render_process_host,
    resource_coordinator::mojom::ProcessCoordinationUnitRequest request) {
  render_process_host->GetProcessResourceCoordinator()->AddBinding(
      std::move(request));
}

} // namespace

class ApplicationSandboxedProcessLauncherDelegate
    : public common::SandboxedProcessLauncherDelegate {
 public:
  ApplicationSandboxedProcessLauncherDelegate(const base::FilePath& application_path):
  application_path_(application_path) {
    
  }
  ~ApplicationSandboxedProcessLauncherDelegate() override {}
#if defined(OS_WIN)
  bool PreSpawnTarget(sandbox::TargetPolicy* policy) override {
    service_manager::SandboxWin::AddBaseHandleClosePolicy(policy);
    const base::string16& sid =
        common::GetClient()->host()->GetAppContainerSidForSandboxType(
            GetSandboxType());
    if (!sid.empty())
      service_manager::SandboxWin::AddAppContainerPolicy(policy, sid.c_str());
    return common::GetClient()->host()->PreSpawnApplication(policy);
  }
#endif  // OS_WIN
#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  common::ZygoteHandle GetZygote() override {
    DLOG(INFO) << "ApplicationSandboxedProcessLauncherDelegate::GetZygote";
    // const base::CommandLine& browser_command_line =
    //     *base::CommandLine::ForCurrentProcess();
    // base::CommandLine::StringType renderer_prefix =
    //     browser_command_line.GetSwitchValueNative(switches::kRendererCmdPrefix);
    // if (!renderer_prefix.empty())
    //   return nullptr;
    return common::GetGenericZygote();
  }
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

#if defined(OS_POSIX)
  base::EnvironmentMap GetEnvironment() override {
    base::EnvironmentMap env_map;
    base::FilePath sdk_path;
    base::PathService::Get(common::DIR_APP, &sdk_path);
    env_map["LD_LIBRARY_PATH"] = sdk_path.value();//application_path_.DirName().value();
    env_map["ICU_DATA"] = sdk_path.value();//application_path_.DirName().value();
 #if defined(USE_GLIB)
    env_map["G_SLICE"] = "always-malloc";
#endif
    return env_map;
  }
#endif  // defined(OS_POSIX)

  service_manager::SandboxType GetSandboxType() override {
    return service_manager::SANDBOX_TYPE_APPLICATION;
  }

private:
  base::FilePath application_path_;
};

class ApplicationProcessHost::ConnectionFilterController
    : public base::RefCountedThreadSafe<ConnectionFilterController> {
 public:
  // |filter| is not owned by this object.
  explicit ConnectionFilterController(ConnectionFilterImpl* filter)
      : filter_(filter) {}

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

class ApplicationProcessHost::ConnectionFilterImpl : public common::ConnectionFilter {
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

    if (!registry_->TryBindInterface(interface_name, interface_pipe)) {
      DLOG(ERROR) << "ApplicationProcessHost: trying to bind service interface '" << interface_name << "' on " <<
                     "non-binded service.\n" <<
                     "source_info.identity.name: " << source_info.identity.name() << "source_info.identity.instance: " << source_info.identity.instance() << " interface_name: " << interface_name;
    }
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

// static
ApplicationProcessHost::iterator ApplicationProcessHost::AllHostsIterator() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //return iterator(g_all_hosts.Pointer());
  // TODO: see if we dont get in trouble for using this
  base::IDMap<ApplicationProcessHost*>& hosts = GetAllHosts();
  return iterator(&hosts);
}

// static 
ApplicationProcessHost* ApplicationProcessHost::FromID(int32_t process_id) {
  ApplicationProcessHost* host = GetAllHosts().Lookup(process_id);
  return host;  
}

void ApplicationProcessHost::ConnectionFilterController::DisableFilter() {
  base::AutoLock lock(lock_);
  if (filter_)
    filter_->Disable();
}

ApplicationProcessHost::ApplicationProcessHost(base::WeakPtr<Application> application):
  application_(std::move(application)),
  route_provider_binding_(this),
  priority_({
        true,//blink::kLaunchingProcessIsBackgrounded, 
        0,
        false//blink::kLaunchingProcessIsBoostedForPendingView
      }),
  application_host_binding_(this),
  // TODO: check the ownership, giving we share this with ApplicationContents
  //application_window_host_(new ApplicationWindowHost()),
  sudden_termination_allowed_(true),
  ignore_input_events_(false),
  id_(common::ChildProcessHostImpl::GenerateChildProcessUniqueId()),
  //available_(true),
  is_shutting_down_(false),
  is_dead_(true),
  is_initialized_(false),
  channel_connected_(false),
  gpu_observer_registered_(false),
  headless_(application_->headless()),
  media_stream_count_(0),
  weak_factory_(this) {

  window_helper_ = new ApplicationWindowHelper();
  RegisterHost(GetID(), this);

    //InitializeChannelProxy();
  gpu_client_.reset(new GpuClient(GetID()));
  application_->AttachProcess(this);
  domain_ = application_->domain();
  application_name_ = application_->name();
  application_uuid_ = application_->id();
  application_url_ = application_->initial_url();
  application_driver_ = application_->application_driver();
  
  //DLOG(INFO) << "ApplicationProcessHost: creating network context.. ";
  // network::mojom::NetworkContextParamsPtr network_context_params = 
  //   network::mojom::NetworkContextParams::New();
  // GetNetworkService()->CreateNetworkContext(
  //   mojo::MakeRequest(&network_context_),
  //   std::move(network_context_params));
}

ApplicationProcessHost::~ApplicationProcessHost() {
  loader_task_runner_ = nullptr;
  if (gpu_observer_registered_) {
    ui::GpuSwitchingManager::GetInstance()->RemoveObserver(this);
    gpu_observer_registered_ = false;
  }
  ChildProcessSecurityPolicyImpl::GetInstance()->Remove(GetID());
  is_dead_ = true;
  if (application_) {
    application_->DetachProcess(this);
  }
  //UnregisterHost(GetID());
}

Runnable* ApplicationProcessHost::runnable() const {
  return application_.get();
}

bool ApplicationProcessHost::Init() {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  base::FilePath command_path;

  if (is_initialized_) {
    return true;
  }

  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  application_root_ = domain_->partition_path();
  application_executable_ = workspace->GetApplicationExecutablePath(application_name_);
  //loader_task_runner_ = base::CreateSingleThreadTaskRunnerWithTraits(
  //  {base::MayBlock(), 
     //base::WithBaseSyncPrimitives(), 
  //   base::TaskPriority::USER_BLOCKING,
  //   base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
  //   base::SingleThreadTaskRunnerThreadMode::SHARED);

  loader_task_runner_ = HostThread::GetTaskRunnerForThread(HostThread::IO);

  //loader_task_runner_->PostTask(
  //  FROM_HERE,
  //  base::BindOnce(
  //    &ApplicationProcessHost::BuildNetworkContext,
  //    base::Unretained(this)));
  BuildNetworkContext();
  
  frame_sink_provider_.reset(new FrameSinkProviderImpl(domain_, id_));

  const base::CommandLine& host_command_line =
      *base::CommandLine::ForCurrentProcess();

// #if defined(OS_LINUX)
//   int child_flags = common::ChildProcessHost::CHILD_ALLOW_SELF;
// #else
//   int child_flags = common::ChildProcessHost::CHILD_NORMAL;
// #endif
  
  command_path = application_executable_;

  if (gpu_client_) {
    gpu_client_->PreEstablishGpuChannel();
  }

  is_initialized_ = true;
  is_dead_ = false;

  if (!channel_)
    InitializeChannelProxy();

  channel_->Unpause(false /* flush */);

  // Call the embedder first so that their IPC filters have priority.
  service_manager::mojom::ServiceRequest service_request;
  common::GetClient()->host()->ApplicationProcessWillLaunch(this,
                                                            &service_request);
  if (service_request.is_pending()) {
    GetApplicationInterface()->CreateEmbedderApplicationService(
        std::move(service_request));
  }

  CreateMessageFilters();

  RegisterMojoInterfaces();

  std::unique_ptr<base::CommandLine> cmd_line = std::make_unique<base::CommandLine>(command_path);
  cmd_line->AppendSwitchASCII(switches::kApplicationProcess, "");
    
  cmd_line->AppendSwitchASCII(service_manager::switches::kServicePipeToken,
                                    child_connection_->service_token());
  cmd_line->AppendSwitchASCII(switches::kServiceRequestChannelToken,
                              child_connection_->service_token());

  // a uuid we use to uniquely identify the app, and also as a named pipe
  // connection token
  cmd_line->AppendSwitchASCII(switches::kWorkspaceId, domain_->workspace()->name());
  cmd_line->AppendSwitchASCII(switches::kDomainUUID, domain_->id().to_string());
  cmd_line->AppendSwitchASCII(switches::kDomainName, domain_->name());
  cmd_line->AppendSwitchASCII("uuid", application_uuid_.to_string());
  cmd_line->AppendSwitchASCII("application-process-id", base::NumberToString(id_)); 
  cmd_line->AppendSwitchASCII("application-window-id", base::NumberToString(application_window_host_->routing_id()));
  cmd_line->AppendSwitchASCII("url", application_url_.spec());
  if (headless_) {
    cmd_line->AppendSwitchASCII("headless", "");
  }
  cmd_line->CopySwitchesFrom(host_command_line, kSwitchNames,
                            arraysize(kSwitchNames));
  HostChildProcessHostImpl::CopyTraceStartupFlags(cmd_line.get());
  HostChildProcessHostImpl::CopyFeatureAndFieldTrialFlags(cmd_line.get());

  //DLOG(INFO) << "ApplicationProcessHost::Init: " << cmd_line->GetCommandLineString();
  
  child_process_launcher_ = std::make_unique<ChildProcessLauncher>(
          std::make_unique<ApplicationSandboxedProcessLauncherDelegate>(application_executable_),
          std::move(cmd_line), GetID(), this, std::move(broker_client_invitation_),
          base::BindRepeating(&ApplicationProcessHost::OnMojoError, id_),
          true, /*named pipe*/
          true /*terminate_on_shutdown*/);

  channel_->Pause();

  if (!gpu_observer_registered_) {
    gpu_observer_registered_ = true;
    ui::GpuSwitchingManager::GetInstance()->AddObserver(this);
  }

  init_time_ = base::TimeTicks::Now();

  return is_initialized_;
}

void ApplicationProcessHost::InitializeChannelProxy() {
  DCHECK(application_window_host_);

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
    //if (!common::ServiceManagerConnection::GetForProcess()) {
      // Additionally, some test code may not initialize the process-wide
      // ServiceManagerConnection prior to this point. This class of test code
      // doesn't care about render processes, so we can initialize a dummy
      // connection.
    //  common::ServiceManagerConnection::SetForProcess(common::ServiceManagerConnection::Create(
    //      mojo::MakeRequest(&test_service_), io_task_runner));
    //}
    connector = common::ServiceManagerConnection::GetForProcess()->GetConnector();
  }

  // Establish a ServiceManager connection for the new render service instance.
  broker_client_invitation_ =
      std::make_unique<mojo::edk::OutgoingBrokerClientInvitation>();
  service_manager::Identity child_identity(
      common::mojom::kApplicationServiceName,
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
  channel_->GetRemoteAssociatedInterface(&application_interface_);
  channel_->GetRemoteAssociatedInterface(&application_window_host_->application_window_interface_);
  // NOTE: added this here
  channel_->GetRemoteAssociatedInterface(&application_window_host_->associated_widget_input_handler_);

  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&RouteRegistry::AddBinding,
                 base::Unretained(workspace->route_registry())));

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ChannelManager::AddBinding,
                 base::Unretained(workspace->channel_manager())));

   // FIXME: forcing this out of ServiceWorker/SharedWorker
  //        once a ServiceWorker is launched on the application 
  //        process, this will probably try to rebind itself again
  //        so it will break

  // from: renderer_interface_binders.cc
  DomainProcessHost* domain_process = domain()->process();
  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(
      &DomainProcessHost::BindAssociatedCacheStorage,
      base::Unretained(domain_process)));

  //automation

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindAnimationClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
  base::Bind(&ApplicationDriver::BindPageClient,
              application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindOverlayClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindWorkerClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindStorageClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindNetworkClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindLayerTreeClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindHeadlessClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindDOMStorageClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindDatabaseClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindEmulationClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindDOMClient,
               application_driver_));

  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindCSSClient,
               application_driver_));
  
  channel_->AddAssociatedInterfaceForIOThread(
    base::Bind(&ApplicationDriver::BindApplicationCacheClient,
               application_driver_));
  
  application_window_host_->SetUpMojo();
  application_window_host_->SetupInputRouter();
  
  //channel_->GetRemoteAssociatedInterface(&application_window_host_->widget_input_handler_);
  // We start the Channel in a paused state. It will be briefly unpaused again
  // in Init() if applicable, before process launch is initiated.
  channel_->Pause();

}

void ApplicationProcessHost::ResetChannelProxy() {
  if (!channel_)
    return;

  channel_.reset();
  channel_connected_ = false;
}

service_manager::Connector* ApplicationProcessHost::GetConnector() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // TODO: see if this is really what we want. really binded to IO
  //       or another thread? (NOTE: this is being used by service workers)
  service_manager::Connector* connector =
       ServiceManagerContext::GetConnectorForIOThread();
  if (!connector) {
    connector = common::ServiceManagerConnection::GetForProcess()->GetConnector();
  }
  return connector;
}

int ApplicationProcessHost::GetNextRoutingID() {
  return window_helper_->GetNextRoutingID();
}

void ApplicationProcessHost::SetWindow(std::unique_ptr<ApplicationWindowHost> window) {
  application_window_host_ = std::move(window);
  if (resource_message_filter_) {
    resource_message_filter_->set_routing_id(application_window_host_->routing_id());
  }
  //application_window_host_->AttachProcess(this);
}

void ApplicationProcessHost::DestroyWindow() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  if (application_window_host_) {
    application_window_host_.reset();
  }
}

RendererAudioOutputStreamFactoryContext*
ApplicationProcessHost::GetRendererAudioOutputStreamFactoryContext() {
  if (!audio_output_stream_factory_context_) {
    media::AudioManager* audio_manager =
        HostMainLoop::GetInstance()->audio_manager();
    DCHECK(audio_manager) << "AudioManager is not instantiated: running the "
                             "audio service out of process?";
    MediaStreamManager* media_stream_manager =
        HostMainLoop::GetInstance()->media_stream_manager();
    media::AudioSystem* audio_system =
        HostMainLoop::GetInstance()->audio_system();
    audio_output_stream_factory_context_.reset(
        new RendererAudioOutputStreamFactoryContextImpl(
            GetID(), audio_system, audio_manager, media_stream_manager));
  }
  return audio_output_stream_factory_context_.get();
}

scoped_refptr<net::URLRequestContextGetter> ApplicationProcessHost::GetUrlRequestContextGetter() {
  return domain_->GetURLRequestContext();
}

common::mojom::Application* ApplicationProcessHost::GetApplicationInterface() {
  return application_interface_.get();
}

common::mojom::ApplicationWindow* ApplicationProcessHost::GetApplicationWindowInterface() {
  return application_window_host_->GetApplicationWindowInterface();
}

common::mojom::RouteProvider* ApplicationProcessHost::GetRemoteRouteProvider() {
  return remote_route_provider_.get();
}

scoped_refptr<BackgroundFetchContext> ApplicationProcessHost::GetBackgroundFetchContext() {
  return nullptr;
}

void ApplicationProcessHost::AddFilter(HostMessageFilter* filter) {
  filter->RegisterAssociatedInterfaces(channel_.get());
  channel_->AddFilter(filter->GetFilter());
}

const service_manager::Identity& ApplicationProcessHost::GetChildIdentity()
    const {
  return child_connection_->child_identity();
}

void ApplicationProcessHost::SetSuddenTerminationAllowed(bool enabled) {
  sudden_termination_allowed_ = enabled;
}

bool ApplicationProcessHost::SuddenTerminationAllowed() const {
  return sudden_termination_allowed_;
}

// static 
void ApplicationProcessHost::ReleaseOnCloseACK(ApplicationProcessHost* host, int view_route_id) {
  // theres nothing here for us
  // maybe consider removing this
}

void ApplicationProcessHost::PostTaskWhenProcessIsReady(base::OnceClosure task) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(!task.is_null());
  new ApplicationProcessHostIsReadyObserver(this, std::move(task));
}

void ApplicationProcessHost::CreateMessageFilters() {
  //IOThread* io_thread = controller->io_thread();
  //scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  // scoped_refptr<net::URLRequestContextGetter> request_context = domain_->GetURLRequestContext());
  // p2p_socket_dispatcher_host_ = new P2PSocketDispatcherHost(workspace, domain_, request_context.get());
  // AddFilter(p2p_socket_dispatcher_host_.get());


  //AddFilter(new ResourceSchedulerFilter(GetID()));
  //MediaInternals* media_internals = MediaInternals::GetInstance();
  // Add BrowserPluginMessageFilter to ensure it gets the first stab at messages
  // from guests.

  scoped_refptr<net::URLRequestContextGetter> request_context(
      domain_->GetURLRequestContext());
  //scoped_refptr<RenderMessageFilter> render_message_filter(
  //    new RenderMessageFilter(
  //        GetID(), GetBrowserContext(), request_context.get(),
  //        widget_helper_.get(), media_internals,
  //        storage_partition_impl_->GetDOMStorageContext(),
  //        storage_partition_impl_->GetCacheStorageContext()));
  //AddFilter(render_message_filter.get());

  //render_frame_message_filter_ = new RenderFrameMessageFilter(
  //    GetID(),
//      GetBrowserContext(), storage_partition_impl_, widget_helper_.get());
 // AddFilter(render_frame_message_filter_.get());

  ResourceContext* resource_context = domain_->GetResourceContext();

  scoped_refptr<net::URLRequestContextGetter> media_request_context(
      domain_->GetMediaURLRequestContext());

  ResourceMessageFilter::GetContextsCallback get_contexts_callback(base::Bind(
      &GetContexts, resource_context, request_context, media_request_context));

  // Several filters need the Blob storage context, so fetch it in advance.
  scoped_refptr<ChromeBlobStorageContext> blob_storage_context = domain_->GetBlobStorageContext();
      //ChromeBlobStorageContext::GetFor(domain_);

  scoped_refptr<Workspace> workspace = domain_->workspace();
  resource_message_filter_ = new ResourceMessageFilter(
      domain_->GetAppCacheService(),
      blob_storage_context.get(),
      domain_->GetFileSystemContext(),
      domain_->GetServiceWorkerContext().get(),
      domain_->GetPrefetchURLLoaderService(),
      std::move(get_contexts_callback),
      HostThread::GetTaskRunnerForThread(HostThread::IO),
      workspace->route_registry(),
      GetID());

  AddFilter(resource_message_filter_.get());

  if (application_window_host_) {
    resource_message_filter_->set_routing_id(application_window_host_->routing_id());
  }

  AddFilter(
      new MidiHost(GetID(), HostMainLoop::GetInstance()->midi_service()));
  //AddFilter(new DOMStorageMessageFilter(
  //    storage_partition_impl_->GetDOMStorageContext()));

//#if BUILDFLAG(ENABLE_WEBRTC)
  peer_connection_tracker_host_ = new PeerConnectionTrackerHost(GetID());
  AddFilter(peer_connection_tracker_host_.get());
//#endif
  AddFilter(new FileAPIMessageFilter(
      GetID(), GetUrlRequestContextGetter().get(),//domain_->GetURLRequestContext(),
      domain_->GetFileSystemContext(),
      blob_storage_context.get()));
  AddFilter(new BlobDispatcherHost(GetID(), blob_storage_context));
#if defined(OS_MACOSX)
  AddFilter(new TextInputClientMessageFilter());
#endif

  p2p_socket_dispatcher_host_ = new P2PSocketDispatcherHost(
    domain_->workspace(), domain_, request_context.get(),
    domain_->workspace()->domain_socket_acceptor());
  AddFilter(p2p_socket_dispatcher_host_.get());
  
  scoped_refptr<ServiceWorkerDispatcherHost> service_worker_filter =
    domain_->GetServiceWorkerDispatcherHostForApplication(GetID());
  scoped_refptr<ServiceWorkerContextWrapper> service_worker_context = domain_->GetServiceWorkerContext();
  service_worker_filter->Init(service_worker_context.get());
  AddFilter(service_worker_filter.get());

  notification_message_filter_ = new NotificationMessageFilter(
      GetID(), domain_->GetPlatformNotificationContext(),
      resource_context, service_worker_context, domain_);
  AddFilter(notification_message_filter_.get());
}

void ApplicationProcessHost::RegisterMojoInterfaces() {
  std::unique_ptr<service_manager::BinderRegistry> registry = std::make_unique<service_manager::BinderRegistry>();
  associated_interfaces_.reset(new common::AssociatedInterfaceRegistryImpl());

  blink::AssociatedInterfaceRegistry* associated_registry =
      associated_interfaces_.get();

  AddUIThreadInterface(
      registry.get(),
      base::Bind(&Domain::CreateOffscreenCanvasProvider,
                 base::Unretained(domain_)));

  //AddUIThreadInterface(
  //    registry.get(),
  //    base::Bind(&ApplicationProcessHost::CreateEmbeddedFrameSinkProvider,
  //               base::Unretained(this)));

  AddUIThreadInterface(registry.get(),
                       base::Bind(&ApplicationProcessHost::BindFrameSinkProvider,
                                  base::Unretained(this)));

  AddUIThreadInterface(
      registry.get(),
      base::Bind(&ApplicationProcessHost::BindCompositingModeReporter,
                 base::Unretained(this)));
  
  //if (base::FeatureList::IsEnabled(features::kMemoryCoordinator)) {
  //  AddUIThreadInterface(
  //      registry.get(), base::Bind(&CreateMemoryCoordinatorHandle, GetID()));
  //}

  if (resource_coordinator::IsResourceCoordinatorEnabled()) {
    AddUIThreadInterface(
        registry.get(),
        base::Bind(&CreateProcessResourceCoordinator, base::Unretained(this)));
  }

  if (gpu_client_) {
    // |gpu_client_| outlives the registry, because its destruction is posted to
    // IO thread from the destructor of |this|.
    registry->AddInterface(
        base::Bind(&GpuClient::Add, base::Unretained(gpu_client_.get())));
  }

  channel_->AddAssociatedInterfaceForIOThread(
      base::Bind(&ApplicationWindowHost::AddBinding,
                 base::Unretained(application_window_host_.get())));


  //common::GetClient()->host()->ExposeInterfacesToDomain(
  //    registry.get(), associated_interfaces_.get(), this);
  
  associated_registry->AddInterface(base::Bind(
      &ApplicationProcessHost::BindRouteProvider, base::Unretained(this)));

  associated_registry->AddInterface(base::Bind(
      &ApplicationProcessHost::CreateApplicationHost, base::Unretained(this)));

  if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    //AddUIThreadInterface(
    //    registry.get(),
    registry->AddInterface(
        base::Bind(&ApplicationProcessHost::CreateURLLoaderFactory,
                   base::Unretained(this)));
  }

  AddUIThreadInterface(
      registry.get(),
      base::Bind(&BroadcastChannelProvider::Connect,
                 base::Unretained(
                     domain_->GetBroadcastChannelProvider())));

  registry->AddInterface(
      base::BindRepeating(&BlobRegistryWrapper::Bind,
                          domain_->GetBlobRegistry(), GetID()));


  // FIXME: forcing this out of ServiceWorker/SharedWorker
  //        once a ServiceWorker is launched on the application 
  //        process, this will probably try to rebind itself again
  //        so it will break

  // from: renderer_interface_binders.cc
  
  // registry->AddInterface(
  //     base::Bind([this](blink::mojom::NotificationServiceRequest request) {
  //       DLOG(INFO) << "ApplicationProcessHost: create notification service ..";
  //       url::Origin origin = url::Origin::Create(this->application_url_);
  //       this->domain()->GetPlatformNotificationContext()->CreateService(host->GetID(), origin, std::move(request));
  // }));
  
  url::Origin origin = url::Origin::Create(this->application_url_);
  registry->AddInterface(
      base::BindRepeating(&BackgroundFetchServiceImpl::CreateWithArgs, base::Unretained(this), origin)); 

  
  common::ServiceManagerConnection* service_manager_connection =
      common::ServiceManagerConnection::GetForProcess();
      //ApplicationContents::GetServiceManagerConnectionFor(application_contents_);
  std::unique_ptr<ConnectionFilterImpl> connection_filter(
      new ConnectionFilterImpl(child_connection_->child_identity(),
                               std::move(registry)));
  connection_filter_controller_ = connection_filter->controller();
  connection_filter_id_ = service_manager_connection->AddConnectionFilter(
      std::move(connection_filter));
}

void ApplicationProcessHost::BindRouteProvider(
    common::mojom::RouteProviderAssociatedRequest request) {
  if (route_provider_binding_.is_bound())
    return;
  route_provider_binding_.Bind(std::move(request));
}

void ApplicationProcessHost::GetRoute(
    int32_t routing_id,
    common::mojom::AssociatedInterfaceProviderAssociatedRequest request) {
  DCHECK(request.is_pending());
  associated_interface_provider_bindings_.AddBinding(
      this, std::move(request), routing_id);
}

void ApplicationProcessHost::GetAssociatedInterface(
    const std::string& name,
    common::mojom::AssociatedInterfaceAssociatedRequest request) {
  int32_t routing_id =
      associated_interface_provider_bindings_.dispatch_context();
  IPC::Listener* listener = listeners_.Lookup(routing_id);
  if (listener)
    listener->OnAssociatedInterfaceRequest(name, request.PassHandle());
}

void ApplicationProcessHost::BindInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  child_connection_->BindInterface(interface_name, std::move(interface_pipe));
}

void ApplicationProcessHost::CreateApplicationHost(
    common::mojom::ApplicationHostAssociatedRequest request) {
  application_host_binding_.Bind(std::move(request));
}

void ApplicationProcessHost::CreateURLLoaderFactory(
    network::mojom::URLLoaderFactoryRequest request) {
  if (!base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    NOTREACHED();
    return;
  }
  GetNetworkContext()->CreateURLLoaderFactory(
      std::move(request), id_);
}

void ApplicationProcessHost::EnableSendQueue() {
  if (!channel_)
    InitializeChannelProxy();
}

void ApplicationProcessHost::AddObserver(ApplicationProcessHostObserver* observer) {
  observers_.AddObserver(observer);
}

void ApplicationProcessHost::RemoveObserver(ApplicationProcessHostObserver* observer) {
  observers_.RemoveObserver(observer);
}

void ApplicationProcessHost::AddRoute(int32_t routing_id, IPC::Listener* listener) {
 listeners_.AddWithID(listener, routing_id);
}

void ApplicationProcessHost::RemoveRoute(int32_t routing_id) {
 listeners_.Remove(routing_id);
 //Cleanup();
}

void ApplicationProcessHost::AddWindow(ApplicationWindowHost* window) {
  windows_.insert(window);
  //DCHECK(!base::ContainsKey(priority_clients_, window));
  //priority_clients_.insert(window);
  //UpdateProcessPriorityInputs();
}

void ApplicationProcessHost::RemoveWindow(ApplicationWindowHost* window) {
  windows_.erase(window);
  //DCHECK(base::ContainsKey(priority_clients_, window));
  //priority_clients_.erase(window);
  //UpdateProcessPriorityInputs();
}

void ApplicationProcessHost::OnMediaStreamAdded() {
  ++media_stream_count_;
//  UpdateProcessPriority();
}

void ApplicationProcessHost::OnMediaStreamRemoved() {
  DCHECK_GT(media_stream_count_, 0);
  --media_stream_count_;
 // UpdateProcessPriority();
}

int ApplicationProcessHost::GetID() const {
 return id_;
}

bool ApplicationProcessHost::HasConnection() const {
 return channel_.get() != NULL;
}

void ApplicationProcessHost::CleanupOnIO() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (application_window_host_) {
    application_window_host_->DestroyOnIO();
  }
  
}

void ApplicationProcessHost::Cleanup() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (application_window_host_) {
    application_window_host_->Destroy(false);
  }

  frame_sink_provider_->Unbind();

  // if (listeners_.IsEmpty()) {
  //   //base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
  //   channel_.reset();
  // }
  // Until there are no other owners of this object, we can't delete ourselves.
  // if (!listeners_.IsEmpty()) {
  //   DLOG(INFO) << "ApplicationProcessHost::Cleanup: listeners_.IsEmpty() = false. cancelling";
  //   return;
  // }

  // if (HasConnection() && child_process_launcher_.get()) {
  //   // Populates Android-only fields and closes the underlying base::Process.
  //   ChildProcessTerminationInfo info =
  //       child_process_launcher_->GetChildTerminationInfo(
  //           false /* already_dead */);
  //   info.status = base::TERMINATION_STATUS_NORMAL_TERMINATION;
  //   info.exit_code = 0;
  //   for (auto& observer : observers_) {
  //     observer.ApplicationProcessExited(this, info);
  //   }
  // }

  audio_output_stream_factory_context_.reset();

  DestroyWindow();
  
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

  UnregisterHost(GetID());


  //DLOG(INFO) << "ApplicationProcessHost::Cleanup calling delete soon";
  //base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);

  for (auto& observer : observers_) {
    observer.ApplicationProcessHostDestroyed(this);
  }
  
  HostThread::DeleteSoon(HostThread::UI, FROM_HERE, this);
}

IPC::ChannelProxy* ApplicationProcessHost::GetChannelProxy() {
 return channel_.get();
}

bool ApplicationProcessHost::Shutdown(int exit_code) {
  if (!child_process_launcher_.get())
    return false;

  return child_process_launcher_->Terminate(exit_code);
}

// bool ApplicationProcessHost::Shutdown(int exit_code, bool wait) {
//   return false;
// }

void ApplicationProcessHost::OnProcessLaunched() {

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

  NotificationService::current()->Notify(NOTIFICATION_RENDERER_PROCESS_CREATED,
                                         Source<ApplicationProcessHost>(this),
                                         NotificationService::NoDetails());

  if (child_process_launcher_)
    channel_->Flush();

  if (IsReady()) {
    for (auto& observer : observers_)
      observer.ApplicationProcessReady(this);
  }
}

void ApplicationProcessHost::OnProcessLaunchFailed(int error_code) {
  LOG(ERROR) << "process launch failed";
  ChildProcessTerminationInfo info;
  info.status = base::TERMINATION_STATUS_LAUNCH_FAILED;
  info.exit_code = error_code;
  ProcessDied(true, &info);
}

bool ApplicationProcessHost::Send(IPC::Message* msg) {
 std::unique_ptr<IPC::Message> message(msg);
 if (!channel_)
    return false;
    
 return channel_->Send(message.release());
}

bool ApplicationProcessHost::OnMessageReceived(const IPC::Message& msg) {
  //DLOG(INFO) << "ApplicationProcessHost::OnMessageReceived";
  if (msg.routing_id() == MSG_ROUTING_CONTROL) {
    // Dispatch control messages.
    IPC_BEGIN_MESSAGE_MAP(ApplicationProcessHost, msg)
      IPC_MESSAGE_HANDLER(ChildProcessHostMsg_ShutdownRequest, ShutdownRequest)
    IPC_END_MESSAGE_MAP()
  }
  
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationProcessHost::DispatchMessageForListenersOnUI, base::Unretained(this), msg));
 
  // assume true
  return true;
}

void ApplicationProcessHost::DispatchMessageForListenersOnUI(const IPC::Message& message) {
  // Dispatch incoming messages to the appropriate IPC::Listener.i
  IPC::Listener* listener = listeners_.Lookup(message.routing_id());
  if (!listener) {
    if (message.is_sync()) {
      // The listener has gone away, so we must respond or else the caller will
      // hang waiting for a reply.
      IPC::Message* reply = IPC::SyncMessage::GenerateReply(&message);
      reply->set_reply_error();
      Send(reply);
    }
    //return true;
  }
  //return listener->OnMessageReceived(msg);
}

resource_coordinator::ProcessResourceCoordinator*
ApplicationProcessHost::GetProcessResourceCoordinator() {
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

const base::Process& ApplicationProcessHost::GetProcess() const {
  if (!child_process_launcher_.get() || child_process_launcher_->IsStarting()) {
    static const base::NoDestructor<base::Process> null_process;
    return *null_process;
  }

  return child_process_launcher_->GetProcess();
}

bool ApplicationProcessHost::IsReady() const {
  // The process launch result (that sets GetHandle()) and the channel
  // connection (that sets channel_connected_) can happen in either order.
  return GetProcess().Handle() && channel_connected_;
}

// std::unique_ptr<NavigationLoaderInterceptor> ApplicationProcessHost::CreateServiceWorkerInterceptor(
//     const common::NavigationRequestInfo& request_info,
//     ServiceWorkerNavigationHandleCore* service_worker_navigation_handle_core) const {
//   const ResourceType resource_type = request_info.is_main_frame
//                                           ? RESOURCE_TYPE_MAIN_FRAME
//                                           : RESOURCE_TYPE_SUB_FRAME;
//   network::mojom::RequestContextFrameType frame_type =
//       request_info.is_main_frame
//           ? network::mojom::RequestContextFrameType::kTopLevel
//           : network::mojom::RequestContextFrameType::kNested;
//   storage::BlobStorageContext* blob_storage_context = GetBlobStorageContext(
//       GetChromeBlobStorageContextForResourceContext(resource_context_));
//   return ServiceWorkerRequestHandler::InitializeForNavigationNetworkService(
//       *resource_request_, resource_context_,
//       service_worker_navigation_handle_core, blob_storage_context,
//       request_info.begin_params->skip_service_worker, resource_type,
//       request_info.begin_params->request_context_type, frame_type,
//       request_info.are_ancestors_secure, request_info.common_params.post_data,
//       web_contents_getter_);
// }

void ApplicationProcessHost::OnChannelConnected(int32_t peer_pid) {
#if BUILDFLAG(IPC_MESSAGE_LOG_ENABLED)
  child_control_interface_->SetIPCLoggingEnabled(
      IPC::Logging::GetInstance()->Enabled());
#endif
//   HostThread::PostTask(
//     HostThread::UI, 
//     FROM_HERE, 
//     base::BindOnce(&ApplicationProcessHost::OnChannelConnectedImpl, 
//       weak_factory_.GetWeakPtr(), 
//       peer_pid));
  OnChannelConnectedImpl(peer_pid);
}

void ApplicationProcessHost::OnChannelConnectedImpl(int32_t peer_pid) {
  channel_connected_ = true;
  if (IsReady()) {
    for (auto& observer : observers_)
      observer.ApplicationProcessReady(this);
  }  
  //base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
  //  FROM_HERE, 
  //  base::BindOnce(&DomainProcessHost::LoadModuleInternal, 
  //    weak_factory_.GetWeakPtr()),
  //  base::TimeDelta::FromSeconds(10));
}

void ApplicationProcessHost::OnChannelError() {
 LOG(INFO) << "channel error.";
 ProcessDied(true, nullptr);
}

void ApplicationProcessHost::OnBadMessageReceived(const IPC::Message& message) {
 LOG(ERROR) << "bad message " << message.type() << " terminating application.";
 Shutdown(common::RESULT_CODE_KILLED_BAD_MESSAGE);
}

void ApplicationProcessHost::SetIgnoreInputEvents(bool ignore_input_events) {
  if (ignore_input_events == ignore_input_events_)
    return;

  ignore_input_events_ = ignore_input_events;
  for (auto* window : windows_) {
    window->ProcessIgnoreInputEventsChanged(ignore_input_events);
  }
}

bool ApplicationProcessHost::IgnoreInputEvents() const {
  return ignore_input_events_;
}

void ApplicationProcessHost::ShutdownRequest() {
  for (auto& observer : observers_) {
    observer.ApplicationProcessShutdownRequested(this);
  }
  for (auto& observer : observers_) {
    observer.ApplicationProcessWillExit(this);
  }
  child_control_interface_->ProcessShutdown();
}

bool ApplicationProcessHost::FastShutdownIfPossible(size_t page_count,
                                                    bool skip_unload_handlers) {
  // Do not shut down the process if there are active or pending views other
  // than the ones we're shutting down.
  //if (page_count && page_count != (GetActiveViewCount() + pending_views_))
  //  return false;

  //if (run_renderer_in_process())
  //  return false;  // Single process mode never shuts down the renderer.

  if (!child_process_launcher_.get()) {
    return false;  // Render process hasn't started or is probably crashed.
  }

  // Test if there's an unload listener.
  // NOTE: It's possible that an onunload listener may be installed
  // while we're shutting down, so there's a small race here.  Given that
  // the window is small, it's unlikely that the web page has much
  // state that will be lost by not calling its unload handlers properly.
  if (!skip_unload_handlers && !SuddenTerminationAllowed()) {
    DLOG(INFO) << "SuddenTerminationAllowed = false. cancelling shutdown";
    return false;
  }

  // if (keep_alive_ref_count_ != 0) {
  //   if (keep_alive_start_time_.is_null())
  //     keep_alive_start_time_ = base::TimeTicks::Now();
  //   return false;
  // }

  // Set this before ProcessDied() so observers can tell if the render process
  // died due to fast shutdown versus another cause.
  //fast_shutdown_started_ = true;

  //ProcessDied(false /* already_dead */, nullptr);

  HostThread::PostTask(
     HostThread::IO, 
     FROM_HERE, 
     base::BindOnce(
       &ApplicationProcessHost::ProcessDied, 
       base::Unretained(this),
       false, nullptr));
  
  return true;
}

// Handle termination of our process.
void ApplicationProcessHost::ProcessDied(bool already_dead, ChildProcessTerminationInfo* known_info) {
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
      &ApplicationProcessHost::NotifyApplicationProcessExited, 
      weak_factory_.GetWeakPtr(),
      info));

  //base::IDMap<IPC::Listener*>::iterator iter(&listeners_);
  //while (!iter.IsAtEnd()) {
  //  iter.GetCurrentValue()->OnMessageReceived(FrameHostMsg_RenderProcessGone(
  //       iter.GetCurrentKey(), static_cast<int>(info.status), info.exit_code));
  //   iter.Advance();
  //}

  EnableSendQueue();

  // It's possible that one of the calls out to the observers might have caused
  // this object to be no longer needed.
  // if (delayed_cleanup_needed_)
  //Cleanup();

  child_process_launcher_.reset();
  channel_.reset();
  network_context_.reset();
  ResetIPC();
  
  CleanupOnIO();

  HostThread::PostTask(
    HostThread::UI, 
     FROM_HERE, 
     base::BindOnce(
       &ApplicationProcessHost::Cleanup, 
       base::Unretained(this)));
       //weak_factory_.GetWeakPtr()));
}

void ApplicationProcessHost::NotifyApplicationProcessExited(const ChildProcessTerminationInfo& info) {
  for (auto& observer : observers_) {
    observer.ApplicationProcessExited(this, info);
  }
}

void ApplicationProcessHost::BindCacheStorage(
    blink::mojom::CacheStorageRequest request,
    const url::Origin& origin) {
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


void ApplicationProcessHost::ResetIPC() {
  if (application_host_binding_.is_bound())
    application_host_binding_.Unbind();
  if (route_provider_binding_.is_bound())
    route_provider_binding_.Close();
  associated_interface_provider_bindings_.CloseAllBindings();
  associated_interfaces_.reset();

  //offscreen_canvas_provider_.reset();
  remote_route_provider_.reset();
  application_interface_.reset();
  network_context_ptr_.reset();
  compositing_mode_reporter_.reset();
  child_control_interface_.reset();
  child_connection_.reset();
  broker_client_invitation_.reset();
  // If ApplicationProcessHost is reused, the next application will send a new
  // request for FrameSinkProvider so make sure frame_sink_provider_ is ready
  // for that.
  //frame_sink_provider_->Unbind();

  // It's important not to wait for the DeleteTask to delete the channel
  // proxy. Kill it off now. That way, in case the profile is going away, the
  // rest of the objects attached to this RenderProcessHost start going
  // away first, since deleting the channel proxy will post a
  // OnChannelClosed() to IPC::ChannelProxy::Context on the IO thread.
  ResetChannelProxy();
}

void ApplicationProcessHost::OnMojoError(int id,
                                       const std::string& error) {
  LOG(ERROR) << "Terminating shell process for bad Mojo message: " << error;
}

// static 
void ApplicationProcessHost::RegisterHost(int host_id, ApplicationProcessHost* host) {
  GetAllHosts().AddWithID(host, host_id);
}

// static 
void ApplicationProcessHost::UnregisterHost(int host_id) {
  ApplicationProcessHost* host = GetAllHosts().Lookup(host_id);
  if (!host)
    return;

  GetAllHosts().Remove(host_id);
}

void ApplicationProcessHost::OnGpuSwitched() {
  RecomputeAndUpdateWebKitPreferences();
}

void ApplicationProcessHost::RecomputeAndUpdateWebKitPreferences() {
  // We are updating all widgets including swapped out ones.
  for (auto* window : windows_) {
    window->OnWebkitPreferencesChanged();
  }
}

// void ApplicationProcessHost::CreateOffscreenCanvasProvider(
//     blink::mojom::OffscreenCanvasProviderRequest request) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   if (!offscreen_canvas_provider_) {
//     // The client id gets converted to a uint32_t in FrameSinkId.
//     uint32_t application_client_id = base::checked_cast<uint32_t>(id_);
//     offscreen_canvas_provider_ = std::make_unique<OffscreenCanvasProviderImpl>(
//         GetHostFrameSinkManager(), application_client_id);
//   }
//   offscreen_canvas_provider_->Add(std::move(request));
// }

// void ApplicationProcessHost::CreateEmbeddedFrameSinkProvider(
//      blink::mojom::EmbeddedFrameSinkProviderRequest request) {
//   DLOG(INFO) << "ApplicationProcessHost::CreateEmbeddedFrameSinkProvider";
//    DCHECK_CURRENTLY_ON(HostThread::UI);
//    if (!embedded_frame_sink_provider_) {
//      // The client id gets converted to a uint32_t in FrameSinkId.
//      uint32_t application_client_id = base::checked_cast<uint32_t>(id_);
//      embedded_frame_sink_provider_ =
//          std::make_unique<EmbeddedFrameSinkProviderImpl>(
//              GetHostFrameSinkManager(), application_client_id);
//    }
//    embedded_frame_sink_provider_->Add(std::move(request));
// }

void ApplicationProcessHost::BindFrameSinkProvider(common::mojom::FrameSinkProviderRequest request) {
  frame_sink_provider_->Bind(std::move(request));
}

void ApplicationProcessHost::BindCompositingModeReporter(
    viz::mojom::CompositingModeReporterRequest request) {
  HostMainLoop::GetInstance()->GetCompositingModeReporter(
      std::move(request));
}

void ApplicationProcessHost::BuildNetworkContext() {
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

void ApplicationProcessHost::BuildNetworkContextOnIO(
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
  params->context_name = application_name_;
  params->http_cache_enabled = true;
  params->http_cache_path = application_root_.AppendASCII("cache");
  params->enable_data_url_support = true;
  params->enable_file_url_support = true;
  params->enable_ftp_url_support = true;
  network_context_ = std::make_unique<HostNetworkContext>(
        GetNetworkServiceImpl(), 
        mojo::MakeRequest(&network_context_ptr_),
        std::move(params), 
        std::move(builder));
}

}
