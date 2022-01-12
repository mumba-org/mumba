// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain.h"

#include "base/strings/string_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/bind.h"
#include "core/host/application/application_manager_host.h"
#include "core/host/application/application.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/host_controller.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/host/workspace/workspace.h"
#include "core/host/volume/volume.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_controller.h"
#include "core/host/application/url_data_manager.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/prefetch_url_loader_service.h"
#include "core/host/application/domain_automation_host.h"
#include "core/host/application/runnable_manager.h"
#include "core/host/route/route_dispatcher_client.h"
#include "core/host/application/storage_context.h"
#include "core/host/compositor/surface_utils.h"
#include "core/host/background_fetch_delegate.h"
#include "core/host/background_fetch/background_fetch_delegate_factory.h"
#include "core/host/background_fetch/background_fetch_delegate_impl.h"
#include "core/host/background_sync/background_sync_controller_factory.h"
#include "core/host/background_sync/background_sync_controller_impl.h"
#include "core/host/service_worker/service_worker_dispatcher_host.h"
#include "core/host/cache_storage/cache_storage_context_impl.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/background_fetch/background_fetch_context.h"
#include "core/host/route/ipc_url_loader_factory.h"
#include "core/host/streams/stream_context.h"
#include "core/host/blob_storage/blob_registry_wrapper.h"
#include "core/host/blob_storage/chrome_blob_storage_context.h"
#include "core/host/file_url_loader_factory.h"
#include "core/host/fileapi/browser_file_system_helper.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_model.h"
#include "core/host/io_thread.h"
#include "core/host/host_controller.h"
#include "storage/host/quota/quota_settings.h"
#include "net/url_request/url_request_context_getter.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "url/gurl.h"

namespace host {
namespace {

base::WeakPtr<storage::BlobStorageContext> BlobStorageContextGetterForStorage(
    scoped_refptr<ChromeBlobStorageContext> blob_context) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  return blob_context->context()->AsWeakPtr();
}

}

char Domain::kClassName[] = "application";

std::unique_ptr<Domain> Domain::Deserialize(scoped_refptr<Workspace> workspace, net::IOBuffer* buffer, int size) {
  protocol::Domain domain_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!domain_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Domain>(new Domain(workspace, std::move(domain_proto)));
}

// static 
std::unique_ptr<Domain> Domain::New(scoped_refptr<Workspace> workspace, const base::UUID& id, const std::string& name, const base::UUID& volume_id) {
  protocol::Domain proto;
  proto.set_uuid(std::string(reinterpret_cast<const char *>(id.data), 16));
  proto.set_name(name);
  proto.set_container_uuid(std::string(reinterpret_cast<const char *>(volume_id.data), 16));
  return std::unique_ptr<Domain>(new Domain(workspace, std::move(proto)));
}

Domain::Domain(scoped_refptr<Workspace> workspace):
  workspace_(workspace),
  runnable_manager_(workspace->runnable_manager()),
  id_(base::UUID::generate()),
  raw_process_(nullptr),
  data_source_(nullptr),
  main_volume_(nullptr),
  host_manager_(std::make_unique<ApplicationManagerHost>(workspace_->application_controller())),
  managed_(false),
  online_(false),
  shutting_down_(false),
  wait_for_application_shutdown_(false),
  service_worker_process_type_(kPROCESS_TYPE_SERVICE),
  done_(
    base::WaitableEvent::ResetPolicy::AUTOMATIC, 
    base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(this) {
  domain_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));

}

Domain::Domain(scoped_refptr<Workspace> workspace, protocol::Domain domain_info):
  workspace_(workspace),
  runnable_manager_(workspace->runnable_manager()),
  id_(reinterpret_cast<const uint8_t *>(domain_info.uuid().data())),
  container_id_(reinterpret_cast<const uint8_t *>(domain_info.container_uuid().data())),
  domain_proto_(std::move(domain_info)),
  //name_(name),
  //container_id_(container_id),
  raw_process_(nullptr),
  automation_host_(new DomainAutomationHost(this)),
  data_source_(nullptr),
  main_volume_(nullptr),
  host_manager_(std::make_unique<ApplicationManagerHost>(workspace_->application_controller())),
  managed_(false),
  online_(false),
  shutting_down_(false),
  wait_for_application_shutdown_(false),
  service_worker_process_type_(kPROCESS_TYPE_SERVICE),
  done_(
      base::WaitableEvent::ResetPolicy::AUTOMATIC, 
      base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(this) {
  
}

Domain::~Domain() {
  // if (process_) {
  //   process_->RemoveObserver(this);
  // }
  // DLOG(INFO) << "~Domain: END";
}

scoped_refptr<Workspace> Domain::workspace() const {
  return workspace_;
}

service_manager::Connector* Domain::GetConnector() const {
  DCHECK(raw_process_);
  return raw_process_->GetConnector();
}

bool Domain::ShouldLaunchOnInit() const {
  return true;
}

void Domain::Init() {

  bool in_memory = false;
  partition_path_ = workspace_->GetApplicationRootPath(name());
  
  resource_context_.reset(new ResourceContextImpl(this, nullptr, nullptr));

  route_dispatcher_client_.reset(new RouteDispatcherClient(HostThread::GetTaskRunnerForThread(HostThread::IO)));

  quota_manager_ = new storage::QuotaManager(
      in_memory, 
      partition_path_,
      HostThread::GetTaskRunnerForThread(HostThread::IO).get(),
      nullptr,
      base::Bind(&Domain::GetQuotaSettings,
                 weak_factory_.GetWeakPtr()));

  scoped_refptr<storage::QuotaManagerProxy> quota_manager_proxy = quota_manager_->proxy();

  // Each consumer is responsible for registering its QuotaClient during
  // its construction.
  filesystem_context_ = CreateFileSystemContext(
    this, partition_path_, in_memory, quota_manager_proxy.get());

  base::FilePath path = in_memory ? base::FilePath() : partition_path_;
  
  cache_storage_context_ = new CacheStorageContextImpl(this);
  cache_storage_context_->Init(path, quota_manager_proxy);

  service_worker_context_ = new ServiceWorkerContextWrapper(this);

  scoped_refptr<ChromeBlobStorageContext> blob_context =
      ChromeBlobStorageContext::GetFor(this);

  BlobURLLoaderFactory::BlobContextGetter blob_getter =
    base::BindOnce(&BlobStorageContextGetterForStorage, blob_context);
  blob_url_loader_factory_ =
      BlobURLLoaderFactory::Create(std::move(blob_getter));
  
  // DLOG(INFO) << "Domain::Init: platform_notification_context_ = PlatformNotificationContextImpl()"; 
  platform_notification_context_ =
    new PlatformNotificationContextImpl(path, this,
                                         service_worker_context_);
  // DLOG(INFO) << "Domain::Init: platform_notification_context_->Initialize()"; 
  platform_notification_context_->Initialize();

  background_fetch_context_ =
    new BackgroundFetchContext(this, service_worker_context_);

  broadcast_channel_provider_ = new BroadcastChannelProvider();

  background_sync_context_ = new BackgroundSyncContext();
  background_sync_context_->Init(service_worker_context_);

  url_loader_factory_getter_ = new URLLoaderFactoryGetter();

  prefetch_url_loader_service_ =
      base::MakeRefCounted<PrefetchURLLoaderService>(url_loader_factory_getter_);

  service_worker_context_->Init(
      path, quota_manager_proxy.get(), nullptr,//context->GetSpecialStoragePolicy(),
      blob_context.get(), url_loader_factory_getter_.get());
  
  shared_worker_service_ = std::make_unique<SharedWorkerServiceImpl>(service_worker_context_);

  file_factory_ = std::make_unique<FileURLLoaderFactory>(
        partition_path(),
        base::CreateSequencedTaskRunnerWithTraits(
            {base::MayBlock(), base::TaskPriority::BACKGROUND,
              base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN}));
  
  blob_registry_ = BlobRegistryWrapper::Create(blob_context, filesystem_context_);

  url_loader_factory_getter_->Initialize(this);

  HostThread::PostTask(HostThread::IO, FROM_HERE,
                       base::BindOnce(&Domain::InitOnIO, base::Unretained(this)));
}

void Domain::InitOnIO() {
  //url_loader_factory_getter_->Initialize(this);
   cache_storage_context_->SetBlobParametersForCache(
    GetURLRequestContext(),
    GetBlobStorageContext());
  
  // Bind guys to ipc that was created lazyly after the process was launched
  process()->AddUIThreadInterface(
      process()->GetBinderRegistry(),
      base::Bind(&BroadcastChannelProvider::Connect,
                 base::Unretained(GetBroadcastChannelProvider())));

  process()->GetBinderRegistry()->AddInterface(
      base::BindRepeating(&BlobRegistryWrapper::Bind,
                          blob_registry_, 
                          process()->GetID()));
  // bind route dispatcher as soon as possible
  process()->GetChannelProxy()->GetRemoteAssociatedInterface(&GetRouteDispatcherClient()->route_dispatcher_);
  
  process()->GetChannelProxy()->AddAssociatedInterfaceForIOThread(
      base::Bind(&RouteDispatcherClient::Bind, 
                  base::Unretained(GetRouteDispatcherClient())));
}

scoped_refptr<net::IOBufferWithSize> Domain::Serialize() const {
  return protocol::SerializeMessage(domain_proto_);
}

Application* Domain::NewApplication(
  int id, 
  const std::string& name, 
  const GURL& url, 
  const base::UUID& uuid, 
  Dock::Type window_mode,
  gfx::Rect initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  return runnable_manager_->NewApplication(
    this, 
    id, 
    name, 
    url, 
    uuid, 
    window_mode,
    initial_bounds,
    window_open_disposition,
    fullscreen,
    headless);
}

std::vector<Runnable*> Domain::runnables() const {
  return runnable_manager_->GetRunnablesForDomain(name());
}

Runnable* Domain::GetRunnable(int id) const {
  return runnable_manager_->GetRunnable(id);
}

bool Domain::HaveRunnable(int id) const {
  return runnable_manager_->HaveRunnable(id);
}

Bundle* Domain::bundle() const {
  return main_volume_->bundle();
}

Application* Domain::GetApplication(int id) const {
  Runnable* r = runnable_manager_->GetRunnable(id);
  if (r && r->type() == RunnableType::APPLICATION) {
    return static_cast<Application*>(r);
  }
  return nullptr;
}

bool Domain::HaveApplication(int id) const {
  Runnable* r = runnable_manager_->GetRunnable(id);
  if (r && r->type() == RunnableType::APPLICATION) {
    return true;
  }
  return false;
}

void Domain::DomainProcessReady(DomainProcessHost* host) {
  online_ = true;
  std::vector<common::mojom::ApplicationInfoPtr> infos;
  
  // TEMPORARY
  common::mojom::ApplicationInfoPtr app = common::mojom::ApplicationInfo::New();
  app->name = name();
  app->url = name() + "://*";
  app->uuid = base::UUID::generate().to_string();
  infos.push_back(std::move(app));

  common::mojom::ApplicationManagerClient* client = host_manager()->GetApplicationManagerClientInterface();
  HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(
    &common::mojom::ApplicationManagerClient::ClientRegisterApplications,
    base::Unretained(client),
    base::Passed(std::move(infos))));
}

void Domain::DomainProcessShutdownRequested(DomainProcessHost* host) {
  //DLOG(INFO) << "Domain::DomainProcessShutdownRequested";
}

void Domain::DomainProcessWillExit(DomainProcessHost* host) {
  //DLOG(INFO) << "Domain::DomainProcessWillExit";
  host->RemoveObserver(this);
  online_ = false;
  //process_ = nullptr;
}

void Domain::DomainProcessExited(DomainProcessHost* host,
                                   const ChildProcessTerminationInfo& info) {
  //DLOG(INFO) << "Domain::DomainProcessExited";
  host->RemoveObserver(this);
  online_ = false;
  //process_ = nullptr;
}

void Domain::DomainProcessHostDestroyed(DomainProcessHost* host) {
  //DLOG(INFO) << "Domain::DomainProcessHostDestroyed";
  //DCHECK_CURRENTLY_ON(HostThread::UI)
  
  // if (process_) {
  //   process_->RemoveObserver(this);
  // }
  //process_ = nullptr;
}

// application listeners

void Domain::OnApplicationLaunched(Application* application) {
  NotifyApplicationLaunched(application);
}

void Domain::OnApplicationInitialized(Application* application) {
  NotifyApplicationInitialized(application);
}

void Domain::OnApplicationShutdownRequested(Application* application) {

}

void Domain::OnApplicationWillExit(Application* application) {

}

void Domain::OnApplicationProcessExited(Application* application,
                                         ApplicationProcessHost* process,
                                         const ChildProcessTerminationInfo& info) {
  NotifyApplicationShutdown(application);
}

void Domain::OnApplicationProcessDestroyed(Application* application,
                                            ApplicationProcessHost* process) {
  //DLOG(INFO) << "Domain::OnApplicationProcessDestroyed: apps count = " << applications_.size();
  DCHECK_CURRENTLY_ON(HostThread::UI);
  RemoveApplication(application);
  int applications = runnable_manager_->GetRunnableCountForDomain(name());
  if (shutting_down_ && wait_for_application_shutdown_ && applications == 0 && process_ui_weak_ptr_) {
    //DLOG(INFO) << "Domain::OnApplicationProcessDestroyed: shutting_down_ = true & applications_ = 0. ProcessShutdownOnIO being called";
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(&Domain::ProcessShutdownOnIO, 
        base::Unretained(this),
        raw_process_,
        base::Callback<void(int)>()));
 }
}

void Domain::RemoveApplication(Application* app) {
  runnable_manager_->RemoveRunnable(app);
}

void Domain::Shutdown(base::Callback<void(int)> callback, bool host_shutdown) {
  shutting_down_ = true;
  DCHECK(main_volume_);
  host_manager_->Shutdown();
  int applications = runnable_manager_->GetRunnableCountForDomain(name());
  if (applications > 0) {
    wait_for_application_shutdown_ = true;
    workspace_->application_controller()->TerminateAllApplications(name());
  }
  service_worker_context_->Shutdown();
  background_sync_context_->Shutdown();
  cache_storage_context_->Shutdown();
  filesystem_context_->Shutdown();
  //database_tracker_->Shutdown();
  if (!host_shutdown) {
    main_volume_->Shutdown(
      base::Bind(&Domain::OnVolumeShutdown, base::Unretained(this), base::Passed(std::move(callback)))
    );
  }
}

void Domain::OnVolumeShutdown(base::Callback<void(int)> callback, int64_t result) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  volumes_.clear();

  main_volume_ = nullptr;
  online_ = false;
  if (!wait_for_application_shutdown_ && process_ui_weak_ptr_) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(&Domain::ProcessShutdownOnIO, 
        base::Unretained(this),
        raw_process_,
        base::Passed(std::move(callback))));
    process_ui_weak_ptr_.reset();
  }
}

void Domain::ProcessShutdownOnIO(DomainProcessHost* process, base::Callback<void(int)> callback) {
  //DLOG(INFO) << "Domain::ProcessShutdownOnIO";
  process->ShutdownRequest();
  process->Shutdown(0, false);
  process_io_weak_ptr_.reset();
  raw_process_ = nullptr;
  HostThread::PostTask(
      HostThread::UI, 
      FROM_HERE, 
      base::BindOnce(&Domain::OnDomainProcessShutdown, 
        base::Unretained(this),
        base::Passed(std::move(callback)),
        net::OK));
}

void Domain::OnDomainProcessLaunched(DomainProcessHost* host) {
  BindProcess(host);

  Init();
}

void Domain::OnDomainProcessShutdown(base::Callback<void(int)> callback, int code) {
  if (!callback.is_null()) {
    std::move(callback).Run(code);
  }
}

void Domain::BindProcess(DomainProcessHost* process) {
  raw_process_ = process;
  process_ui_weak_ptr_ = process->GetWeakPtr();
  process->AddObserver(this);
  // if (service_worker_process_type_ == kPROCESS_TYPE_SERVICE) {
  //   service_worker_worker_dispatcher_host_ = new ServiceWorkerDispatcherHost(kPROCESS_TYPE_SERVICE, raw_process_->GetID(), resource_context_.get());
  // }
}

void Domain::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void Domain::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

bool Domain::HaveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      return true;
    }
  }
  return false;
}

void Domain::NotifyApplicationLaunched(Application* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnApplicationLaunched(this, app);
  }
}

void Domain::NotifyApplicationInitialized(Application* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnApplicationInitialized(this, app);
  }
}

void Domain::NotifyApplicationShutdown(Application* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnApplicationShutdown(this, app);
  }
}

void Domain::NotifyServiceAdded(HostRpcService* service) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDomainServiceAdd(this, service);
  }
}

void Domain::NotifyServiceRemoved(HostRpcService* service) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDomainServiceRemove(this, service);
  }
}

RouteDispatcherClient* Domain::GetRouteDispatcherClient() const {
  return route_dispatcher_client_.get();
}

BackgroundFetchDelegate* Domain::GetBackgroundFetchDelegate() {
  return BackgroundFetchDelegateFactory::GetForDomain(this);
}

BackgroundSyncController* Domain::GetBackgroundSyncController() {
  return BackgroundSyncControllerFactory::GetForDomain(this);
}

ChromeBlobStorageContext* Domain::GetBlobStorageContext() {
  return blob_storage_context_.get();
}

void Domain::SetBlobStorageContext(scoped_refptr<ChromeBlobStorageContext> blob_context) {
  blob_storage_context_ = std::move(blob_context);
}

scoped_refptr<ServiceWorkerContextWrapper> Domain::GetServiceWorkerContext() {
  return service_worker_context_;
}

PlatformNotificationContextImpl* Domain::GetPlatformNotificationContext() {
  return platform_notification_context_.get();
}

StreamContext* Domain::GetStreamContext() {
  return stream_context_.get();
}

CacheStorageContextImpl* Domain::GetCacheStorageContext() {
  return cache_storage_context_.get();
}

BlobURLLoaderFactory* Domain::GetBlobURLLoaderFactory() {
  return blob_url_loader_factory_.get();
}

FileURLLoaderFactory* Domain::GetFileURLLoaderFactory() {
  return file_factory_.get();
}

void Domain::SetStreamContext(const scoped_refptr<StreamContext>& context) {
  stream_context_ = context;
}

void Domain::GetQuotaSettings(storage::OptionalQuotaSettingsCallback callback) {
  storage::GetNominalDynamicSettings(
      partition_path_, false, std::move(callback));
}

net::URLRequestContextGetter* Domain::GetURLRequestContext() {
  // FIXME
  IOThread* io_thread = HostController::Instance()->io_thread();
  return io_thread->system_url_request_context_getter();
  // return url_request_context_.get();
}

void Domain::SetURLRequestContext(
    net::URLRequestContextGetter* url_request_context) {
  url_request_context_ = url_request_context;
}

net::URLRequestContextGetter* Domain::GetMediaURLRequestContext() {
  return media_url_request_context_.get();
}

void Domain::SetMediaURLRequestContext(net::URLRequestContextGetter* media_url_request_context) {
  media_url_request_context_ = media_url_request_context;
}

ChromeAppCacheService* Domain::GetAppCacheService() {
  return appcache_service_.get();
}

storage::FileSystemContext* Domain::GetFileSystemContext() {
  return filesystem_context_.get();
}

PrefetchURLLoaderService* Domain::GetPrefetchURLLoaderService() {
  return prefetch_url_loader_service_.get();
}

BroadcastChannelProvider* Domain::GetBroadcastChannelProvider() {
  return broadcast_channel_provider_.get();
}

SharedWorkerServiceImpl* Domain::GetSharedWorkerService() {
  return shared_worker_service_.get();
}

BlobRegistryWrapper* Domain::GetBlobRegistry() {
  return blob_registry_.get();
}

ServiceWorkerProcessType Domain::GetServiceWorkerProcessType() const {
  return service_worker_process_type_;
}

int Domain::GetServiceWorkerProcessId(int application_process_id) const {
  if (service_worker_process_type_ == kPROCESS_TYPE_SERVICE) {
    return raw_process_->GetID();
  }
  return application_process_id;
}

scoped_refptr<ServiceWorkerDispatcherHost> Domain::GetServiceWorkerDispatcherHostForApplication(int application_process_id) const {
  if (service_worker_process_type_ == kPROCESS_TYPE_APPLICATION) {
    // in this case is one dispatcher for each application
    return scoped_refptr<ServiceWorkerDispatcherHost>(new ServiceWorkerDispatcherHost(kPROCESS_TYPE_APPLICATION, application_process_id, GetResourceContext()));
  }
  DCHECK(raw_process_);
  // in this case is one dispatcher for many applications of the app host
  //return service_worker_worker_dispatcher_host_;
  return scoped_refptr<ServiceWorkerDispatcherHost>(new ServiceWorkerDispatcherHost(kPROCESS_TYPE_SERVICE, raw_process_->GetID(), resource_context_.get()));
}

void Domain::CreateOffscreenCanvasProvider(
    blink::mojom::OffscreenCanvasProviderRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (!offscreen_canvas_provider_) {
    offscreen_canvas_provider_ = std::make_unique<OffscreenCanvasProviderImpl>(GetHostFrameSinkManager());
  }
  offscreen_canvas_provider_->Add(std::move(request));
}

void Domain::AddStorageContext(scoped_refptr<StorageContext> context) {
  contexts_.push_back(context);
}

void Domain::RemoveStorageContext(scoped_refptr<StorageContext> context) {
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    if (it->get() == context.get()) {
      contexts_.erase(it);
      return;
    }
  }
}

void Domain::OnDHTAnnounceReply(Share* share, int peers){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnDHTAnnounceReply(share, peers);
  }
}

void Domain::OnShareMetadataReceived(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareMetadataReceived(share);
  }
}

void Domain::OnShareMetadataError(Share* share, int error){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareMetadataError(share, error);
  }
}

void Domain::OnSharePieceReadError(Share* share, int piece_offset, int error){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePieceReadError(share, piece_offset, error);
  }
}

void Domain::OnSharePiecePass(Share* share, int piece_offset){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePiecePass(share, piece_offset);
  }
}

void Domain::OnSharePieceFailed(Share* share, int piece_offset){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePieceFailed(share, piece_offset);
  }
}

void Domain::OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePieceRead(share, piece, offset, size, block_size, result);
  }
}

void Domain::OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePieceWrite(share, piece, offset, size, block_size, result);
  }
}

void Domain::OnSharePieceFinished(Share* share, int piece_offset){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePieceFinished(share, piece_offset);
  }
}

void Domain::OnSharePieceHashFailed(Share* share, int piece_offset){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePieceHashFailed(share, piece_offset);
  }
}

void Domain::OnShareFileCompleted(Share* share, int piece_offset){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareFileCompleted(share, piece_offset);
  }
}

void Domain::OnShareFinished(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareFinished(share);
  }
}

void Domain::OnShareDownloading(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareDownloading(share);
  }
}

void Domain::OnShareCheckingFiles(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareCheckingFiles(share);
  }
}

void Domain::OnShareDownloadingMetadata(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareDownloadingMetadata(share);
  }
}

void Domain::OnShareSeeding(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareSeeding(share);
  }
}

void Domain::OnSharePaused(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnSharePaused(share);
  }
}

void Domain::OnShareResumed(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareResumed(share);
  }
}

void Domain::OnShareChecked(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareChecked(share);
  }
}

void Domain::OnShareDeleted(Share* share){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareDeleted(share);
  }
}

void Domain::OnShareDeletedError(Share* share, int error){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareDeletedError(share, error);
  }
}

void Domain::OnShareFileRenamed(Share* share, int file_offset, const std::string& name){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareFileRenamed(share, file_offset, name);
  }
}

void Domain::OnShareFileRenamedError(Share* share, int index, int error){ 
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    (*it)->OnShareFileRenamedError(share, index, error);
  }
}

}
