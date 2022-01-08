// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/workspace.h"

#include "base/logging.h"
#include "base/sha1.h"
#include "base/strings/string_piece.h"
#include "base/strings/utf_string_conversions.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/task_scheduler/post_task.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "core/host/application/domain_manager.h"
#include "core/host/application/resource_context.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/url_data_manager_backend.h"
#include "core/host/device/device_manager.h"
#include "core/host/device/device.h"
#include "core/host/bundle/bundle.h"
#include "core/host/volume/volume.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/rpc/services/mumba_services.h"
#include "core/host/workspace/service.h"
#include "core/host/workspace/volume_storage.h"
#include "core/host/workspace/app_storage.h"
#include "core/host/rpc/server/rpc_manager.h"
#include "net/rpc/server/proxy_rpc_handler.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_resolver.h"
#include "core/host/rpc/service_registry.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/schema/schema_model.h"
#include "core/host/schema/schema.h"
#include "core/host/channel/channel_manager.h"
#include "core/host/channel/channel.h"
#include "core/host/channel/channel_model.h"
#include "core/host/repo/repo_manager.h"
#include "core/host/repo/repo_model.h"
#include "core/host/repo/repo.h"
#include "core/host/identity/identity_manager.h"
#include "core/host/identity/identity_model.h"
#include "core/host/identity/identity.h"
#include "core/host/share/share_registry.h"
#include "core/host/share/share.h"
#include "core/host/share/share_database.h"
#include "core/host/share/share_manager.h"
#include "core/host/application/domain_model.h"
#include "core/host/application/application_controller.h"
#include "core/host/application/runnable_manager.h"
#include "core/host/volume/volume_model.h"
#include "core/host/volume/volume_source_model.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_list.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/io_thread.h"
#include "core/host/host.h"
#include "core/host/themes/theme_service.h"
#include "core/host/application/storage_manager.h"
//#include "core/host/ui/window_manager.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/ml/ml_controller.h"
#include "core/host/ml/ml_model_service_dispatcher.h"
#include "core/host/ml/ml_prediction_service_dispatcher.h"
#include "core/host/ml/ml_model.h"
#include "core/host/ml/ml_model_manager.h"
#include "core/host/ml/ml_service_manager.h"
#include "core/host/ads/ads_dispatcher.h"
#include "core/host/ads/ads_manager.h"
#include "core/host/api/api_dispatcher.h"
#include "core/host/api/api_manager.h"
#include "core/host/bundle/bundle_manager.h"
#include "core/host/market/market_dispatcher.h"
#include "core/host/market/market_manager.h"
#include "core/shared/common/paths.h"
#include "storage/db/db.h"
#include "storage/storage.h"
#include "storage/torrent.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/storage_utils.h"
#include "storage/torrent_manager.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "ui/base/resource/resource_bundle.h"
#include "core/host/workspace/workspace_service_dispatcher.h"
#if defined(OS_WIN)
#undef uuid_t
#endif
#include "base/uuid.h"

namespace host {

namespace {

//const char kURLDataManagerBackendKeyName[] = "url_data_manager_backend";

const char kCoreServices[] = "message FetchRequest {\n int64 started_time = 1;\n string content_type = 2;\n string url = 3;\n int64 size = 4;\n bytes data = 5;\n }\nmessage FetchReply {\n int64 size=1;\n  bytes data = 2;\n}\nservice FetchService {\n rpc FetchUnary(FetchRequest) returns (FetchReply);\n rpc FetchClientStream(stream FetchRequest) returns (FetchReply);\n rpc FetchServerStream(FetchRequest) returns (stream FetchReply);\n rpc FetchBidiStream(stream FetchRequest) returns (stream FetchReply);\n }\n";


std::vector<std::string> GetSystemKeyspaces() {
  std::vector<std::string> keyspaces;
  keyspaces.push_back("volume");
  keyspaces.push_back("source");
  keyspaces.push_back("application");
  keyspaces.push_back("schema");
  keyspaces.push_back("identity");
  keyspaces.push_back("graph");
  keyspaces.push_back("channel");
  keyspaces.push_back("repo");
  keyspaces.push_back("share");
  keyspaces.push_back("bundle");
  keyspaces.push_back("ml_model");
  keyspaces.push_back("ml_predictor");
  keyspaces.push_back("ml_dataset");
  return keyspaces;
}

void OnBundleApplicationInstalledFromVolume(int result) {}

}

scoped_refptr<Workspace> Workspace::GetCurrent() {
  scoped_refptr<HostController> controller = HostController::Instance();
  scoped_refptr<Workspace> current = controller->host()->current_workspace();
  return current;
}

scoped_refptr<Workspace> Workspace::New(const std::string& name) {
  return scoped_refptr<Workspace>(new Workspace(name));
}

// static 
scoped_refptr<Workspace> Workspace::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Workspace workspace_schema;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!workspace_schema.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return scoped_refptr<Workspace>(new Workspace(std::move(workspace_schema)));
}

Workspace::Workspace(protocol::Workspace workspace_schema):
  workspace_schema_(std::move(workspace_schema)),
  current_(false),
  initializing_(false),
  initialized_(false),
  first_time_(false),
  data_sources_added_(false),
  next_application_id_(0),
  db_policy_(DatabasePolicy::AlwaysOpen),
  io_thread_(nullptr),
  storage_context_manager_(new StorageManager(this)) {
  id_ = base::UUID(reinterpret_cast<const uint8_t*>(workspace_schema_.uuid().data()));
}

Workspace::Workspace(const std::string& name):
  current_(false),
  initializing_(false),
  initialized_(false),
  first_time_(false),
  data_sources_added_(false),
  next_application_id_(0),
  db_policy_(DatabasePolicy::AlwaysOpen),
  io_thread_(nullptr),
  storage_context_manager_(new StorageManager(this)) {
  id_ = base::UUID::generate();
  workspace_schema_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
  workspace_schema_.set_name(name);
}

Workspace::~Workspace() {
  
}

const base::FilePath& Workspace::volume_dir() const {
  return storage_->volume_dir();
}

const base::FilePath& Workspace::app_dir() const {
  return storage_->app_dir();
}

const base::FilePath& Workspace::tmp_dir() const {
  return storage_->tmp_dir();
}

bool Workspace::Init(const WorkspaceParams& params,
                     IOThread* io_thread, 
                     const scoped_refptr<HostController>& controller,
                     DatabasePolicy db_policy) {
  
  base::FilePath real_path = params.profile_path.AppendASCII(name());
  io_thread_ = io_thread;
  storage_.reset(new WorkspaceStorage(real_path));
  first_time_ = storage_->IsEmpty();

  domain_manager_.reset(new DomainManager(this, controller));
  bundle_manager_.reset(new BundleManager(this));
  volume_manager_.reset(new VolumeManager(this));
  identity_manager_.reset(new IdentityManager());
  rpc_manager_.reset(new RpcManager(this));
  schema_registry_.reset(new SchemaRegistry());
  storage_manager_.reset(new storage::StorageManager(real_path));
  route_registry_.reset(new RouteRegistry(this));
  route_resolver_.reset(new RouteResolver(route_registry_.get()));
  service_registry_.reset(new ServiceRegistry(this));
  workspace_service_dispatcher_.reset(new WorkspaceServiceDispatcher(
    this,
    params.admin_service_host,
    params.admin_service_port));
  repo_manager_.reset(new RepoManager());
  channel_manager_.reset(new ChannelManager());
  device_manager_.reset(new DeviceManager());

  application_controller_.reset(new ApplicationController(this));

  ml_model_manager_.reset(new MLModelManager(real_path.AppendASCII("ml_models")));
  ml_service_manager_.reset(new MLServiceManager());
  ml_model_service_dispatcher_.reset(new MLModelServiceDispatcher(ml_model_manager_.get()));
  ml_prediction_service_dispatcher_.reset(new MLPredictionServiceDispatcher(ml_model_manager_.get(), ml_service_manager_.get()));
  ml_controller_.reset(new MLController(ml_model_manager_.get(), ml_service_manager_.get()));
  runnable_manager_.reset(new RunnableManager());

  share_manager_.reset(new ShareManager(volume_storage()->storage_manager()));
  share_registry_.reset(new ShareRegistry(this, share_manager_.get()));

  ads_manager_.reset(new AdsManager());
  ads_dispatcher_.reset(new AdsDispatcher());
  api_manager_.reset(new APIManager());
  api_dispatcher_.reset(new APIDispatcher());
  market_manager_.reset(new MarketManager());
  market_dispatcher_.reset(new MarketDispatcher());

  domain_manager_->AddObserver(this);
  device_manager_->AddObserver(this);
  channel_manager_->AddObserver(this);
  identity_manager_->AddObserver(this);
  route_registry_->AddObserver(this);
  repo_manager_->AddObserver(this);
  rpc_manager_->AddObserver(this);
  schema_registry_->AddObserver(this);
  volume_manager_->AddObserver(this);
  DockList::AddObserver(this);
  
  storage_manager_->Init(
    base::Bind(&Workspace::OnStorageManagerInit, 
      this, 
      base::Unretained(io_thread),
      db_policy), 
      false);

  domain_socket_acceptor_ = base::CreateSingleThreadTaskRunnerWithTraits(
     { base::MayBlock(), 
       base::WithBaseSyncPrimitives(), 
       base::TaskPriority::USER_VISIBLE}, 
       base::SingleThreadTaskRunnerThreadMode::DEDICATED);
  

  
  return true;
}

void Workspace::Shutdown() {
  base::WaitableEvent event{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED };

  domain_manager_->RemoveObserver(this);
  device_manager_->RemoveObserver(this);
  channel_manager_->RemoveObserver(this);
  identity_manager_->RemoveObserver(this);
  route_registry_->RemoveObserver(this);
  repo_manager_->RemoveObserver(this);
  rpc_manager_->RemoveObserver(this);
  schema_registry_->RemoveObserver(this);
  volume_manager_->RemoveObserver(this);
  DockList::RemoveObserver(this);

  DockList::CloseAllDocksWithWorkspace(this);

  workspace_service_dispatcher_->Shutdown();
  rpc_manager_->Shutdown();
  volume_manager_->Shutdown();
  identity_manager_->Shutdown();
  schema_registry_->Shutdown();
  repo_manager_->Shutdown();
  channel_manager_->Shutdown();
  device_manager_->Shutdown();
  route_registry_->Shutdown();
  service_registry_->Shutdown();
  storage_manager_->Shutdown();
  runnable_manager_->Shutdown();
  share_manager_->Shutdown();
// Disable financial system for now
// market_manager_->Shutdown(&event);
  storage_->Shutdown();
  
  domain_manager_->Shutdown();

  for (auto it = service_handlers_.begin(); it != service_handlers_.end(); it++) {
    delete *it;
  }

  service_handlers_.clear();

  rpc_manager_.reset();  
  //domain_manager_.reset();
  volume_manager_.reset();
  schema_registry_.reset();
  repo_manager_.reset(); 
  channel_manager_.reset(); 
  route_registry_.reset();
  device_manager_.reset();
  bundle_manager_.reset();
  //workspace_service_dispatcher_.reset();
  //storage_manager_.reset();

  initialized_ = false;

}

const base::FilePath& Workspace::root_path() const {
  return storage_->root_dir();
}

VolumeStorage* Workspace::volume_storage() {
  return storage_->volume_storage(); 
}

bool Workspace::HasDomain(const std::string& name) const {
  return domain_manager_->HasDomain(name);
}

bool Workspace::HasDomainUUID(const std::string& uuid) const {
  return domain_manager_->HasDomainUUID(uuid);
}

bool Workspace::HasDomain(const base::UUID& uuid) const {
  return domain_manager_->HasDomain(uuid);
}

bool Workspace::HasDomain(const common::DomainInfo& info) const {
  return domain_manager_->HasDomain(info);
}

bool Workspace::HasDomain(const GURL& url) const {
  return domain_manager_->HasDomain(url);
}

Domain* Workspace::GetDomain(const std::string& name) const {
  return domain_manager_->GetDomain(name);
}

Domain* Workspace::GetDomain(const base::UUID& uuid) const {
  return domain_manager_->GetDomain(uuid);
}

Domain* Workspace::GetDomain(const GURL& url) const {
  return domain_manager_->GetDomain(url);
}

Domain* Workspace::GetDomain(const common::DomainInfo& info) const {
  return domain_manager_->GetDomain(info);
}

const DomainModel::Domains& Workspace::GetDomains() const {
  return domain_manager_->GetDomains();
}

DomainModel::Domains& Workspace::GetDomains() {
  return domain_manager_->GetDomains();
}

base::FilePath Workspace::GetApplicationRootPath(const std::string& domain_name) {
  Domain* host = GetDomain(domain_name);
  if (!host) {
    return base::FilePath();
  }
  AppStorage* app_storage = storage_->app_storage();
  return app_storage->GetDirectory(host->id());
}

base::FilePath Workspace::GetApplicationExecutablePath(const std::string& domain_name) {
  Domain* host = GetDomain(domain_name);
  if (!host) {
    return base::FilePath();
  }
  std::string bundle_path = host->bundle()->application_path();
  std::string application_name = domain_name + "_app";
  AppStorage* app_storage = storage_->app_storage();
  base::FilePath path = app_storage->GetDirectory(host->id());
  base::FilePath file_path = storage::GetPathForArchitecture(application_name, storage::GetHostArchitecture(), storage_proto::PROGRAM);
  return path.AppendASCII(bundle_path).Append(file_path); 
}

void Workspace::CreateDomainFromVolume(Volume* volume, base::Callback<void(int)> cb) {
  base::UUID domain_id = base::UUID::generate();
  CheckoutVolume(volume, domain_id, std::move(cb));
}

void Workspace::CheckoutVolume(Volume* volume, const base::UUID& domain_id, base::Callback<void(int)> cb) {
  AppStorage* app_storage = storage_->app_storage();
  app_storage->CreateDirectory(domain_id);
  base::FilePath path = app_storage->GetDirectory(domain_id);
  volume->CheckoutApp(
    path,
    base::Bind(&Workspace::OnVolumeCheckout, 
      this, 
      base::Unretained(volume), 
      domain_id,
      path,
      base::Passed(std::move(cb)))); 
}

void Workspace::OnVolumeCheckout(Volume* volume, const base::UUID& domain_id, const base::FilePath& path, base::Callback<void(int)> cb, int64_t result) {
  if (result == 0) {
    std::string domain_name = volume->name();
    const base::UUID& volume_id = volume->id(); 
    std::unique_ptr<Domain> domain = Domain::New(
      this,
      domain_id,
      domain_name,
      volume_id);
    domain->AddVolume(volume, true /* is_main */);
    domain_manager_->CreateDomain(std::move(domain), std::move(cb), true /* sync */);
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::WithBaseSyncPrimitives(), base::MayBlock() },
      base::BindOnce(
        &Workspace::InstallSchemaAndLibrariesFromVolumeCheckout, 
        this, 
        base::Unretained(volume), 
        path));
  } else {
    DLOG(ERROR) << "VolumeCheckout: checkout for " << volume->name() <<" failed";
    if (!cb.is_null())
      std::move(cb).Run(result);
  }
}

int Workspace::generate_next_application_id() {
  return ++next_application_id_;
}

void Workspace::CreateDomain(std::unique_ptr<Domain> domain, base::Callback<void(int)> cb) {
  domain_manager_->CreateDomain(std::move(domain), std::move(cb));
}

void Workspace::DestroyDomain(const std::string& name) {
  domain_manager_->DestroyDomain(name);
}

void Workspace::DestroyDomain(const base::UUID& uuid) {
  domain_manager_->DestroyDomain(uuid);
}

void Workspace::LaunchDomain(const base::UUID& uuid, base::Callback<void(int)> callback) {
  domain_manager_->LaunchDomain(uuid, storage_context_manager_.get(), domain_socket_acceptor_, std::move(callback));
}

void Workspace::LaunchDomain(const std::string& name, base::Callback<void(int)> callback) {
  domain_manager_->LaunchDomain(name, storage_context_manager_.get(), domain_socket_acceptor_, std::move(callback));
}

void Workspace::LaunchDomain(Domain* shell, base::Callback<void(int)> callback) {
  domain_manager_->LaunchDomain(shell, storage_context_manager_.get(), domain_socket_acceptor_, std::move(callback));
}

void Workspace::ShutdownDomain(const std::string& name, base::Callback<void(int)> callback) {
  domain_manager_->ShutdownDomain(name, std::move(callback));
}

void Workspace::InsertIdentity(std::unique_ptr<Identity> identity) {
  identity_manager_->InsertIdentity(std::move(identity));
}

void Workspace::RemoveIdentity(Identity* identity) {
  identity_manager_->RemoveIdentity(identity);
}

void Workspace::RemoveIdentity(const base::UUID& uuid) {
  identity_manager_->RemoveIdentity(uuid);
}

void Workspace::AddVolume(storage::Storage* volume_storage, const base::Callback<void(std::pair<bool, base::UUID>)>& callback) {
  Bundle* bundle = bundle_manager_->GetBundle(volume_storage->name());
  DCHECK(bundle);
  volume_manager_->AddVolume(volume_storage, bundle, callback);
}

bool Workspace::IsVolumeInstalled(const base::UUID& id) {
  return volume_manager_->IsVolumeInstalled(id);
}

void Workspace::InstallVolumeSync(const base::FilePath& path, 
  base::Callback<void(std::pair<bool, Volume*>)> callback) {
  InstallVolume(path, std::move(callback), true);   
}

void Workspace::InstallVolumeFromDHTAddressSync(
  const std::string& dht_address_hex, 
  base::Callback<void(std::pair<bool, Volume*>)> callback) {
  storage::StorageManager* manager = volume_storage()->storage_manager();
  //DLOG(INFO) << "Workspace::InstallVolume: cloning storage for pub key " << dht_address_hex;
  manager->CloneStorage(dht_address_hex, 
    base::Bind(
      &Workspace::OnVolumeCloned,
      this,
      dht_address_hex,
      base::Passed(std::move(callback)), 
      sync /* sync */)
  );
}

void Workspace::InstallVolume(
  const base::FilePath& path, 
  base::Callback<void(std::pair<bool, Volume*>)> callback,
  bool sync) {
  #if defined (OS_WIN)
  std::string disk_name = base::UTF16ToASCII(path.BaseName().value());
#else
  std::string disk_name = path.BaseName().value();
#endif
  if (disk_name.empty()) {
    DLOG(ERROR) << "Workspace::InstallVolume: store name in " << path << " is empty.";
    std::move(callback).Run(std::make_pair(false, nullptr));
    return;
  }
  InstallVolume(path, disk_name, std::move(callback), sync);
}

void Workspace::InstallVolume(
  const base::FilePath& path, 
  const std::string& disk_name,
  base::Callback<void(std::pair<bool, Volume*>)> callback,
  bool sync) {
  
  if(!bundle_manager_->IsBundleInstalled(disk_name)) {
    DLOG(INFO) << "Workspace::InstallVolume: IsBundleInstalled for " << disk_name << " = false. installing bundle";
    InstallBundle(disk_name, path, std::move(callback));
    return;
  }
  Bundle* bundle = bundle_manager_->GetBundle(disk_name);
  storage::StorageManager* manager = volume_storage()->storage_manager();
  manager->CreateStorage(
    disk_name,
    base::Bind(&Workspace::OnVolumeStorageCreated,
      this,
      path,
      disk_name,
      base::Unretained(bundle),
      base::Passed(std::move(callback)),
      sync));
}

void Workspace::InstallVolume(
  const base::StringPiece zip_contents, 
  const std::string& disk_name,
  base::Callback<void(std::pair<bool, Volume*>)> callback,
  bool sync) {
  
  InstallBundleFromContents(disk_name, zip_contents, std::move(callback));
}

void Workspace::OnVolumeStorageCreated(
  const base::FilePath& path, 
  const std::string& disk_name,
  Bundle* bundle,
  base::Callback<void(std::pair<bool, Volume*>)> callback,
  bool sync,
  storage::Storage* storage, 
  int result) {
  
  if (result != net::OK) {
    DLOG(ERROR) << "Workspace::InstallVolume: creating storage '" << disk_name << "' failed.";
    return;
  }
  storage::StorageManager* manager = volume_storage()->storage_manager();
  scoped_refptr<storage::Torrent> t = manager->NewTorrent(disk_name);
  manager->AddEntry(
    t,
    disk_name,
    path, 
    base::Bind(
      &Workspace::OnVolumeAddedAsEntry,
      this,
      base::Unretained(storage),
      base::Unretained(bundle),
      base::Passed(std::move(callback)), 
      sync /* sync */),
  disk_name);
}

void Workspace::InsertVolume(Volume* container) {
  volume_manager_->InsertVolume(container);
}

void Workspace::RemoveVolume(Volume* container) {
  volume_manager_->RemoveVolume(container);
}

HostRpcService* Workspace::CreateService(
    const std::string& container,
    const std::string& service_name,
    const std::string& host,
    int port, 
    net::RpcTransportType type,
    scoped_refptr<base::SingleThreadTaskRunner> main_runner,
    std::unique_ptr<net::RpcHandler> rpc_handler) {
  Schema* schema = ResolveSchemaForService(container, service_name);
  if (!schema) {
    DLOG(ERROR) << "Rpc service schema/descriptor for '" << container << "." << service_name << "' not found. " << "It need to ship into the container/shell as a Api";
    return nullptr;
  }
  HostRpcService* rpc_service = rpc_manager_->CreateService(//shell, 
    container, service_name, host, port, type, main_runner, domain_socket_acceptor_, schema, std::move(rpc_handler));
  ServiceHandler* handler = new ServiceHandler(rpc_service, schema);
  AddServiceHandler(handler);
  return rpc_service;
}
  
HostRpcService* Workspace::GetService(const base::UUID& uuid) const {
  return rpc_manager_->GetService(uuid);
}

HostRpcService* Workspace::GetService(const std::string& name) const {
  return rpc_manager_->GetService(name); 
}

void Workspace::AddService(HostRpcService* service) {
  rpc_manager_->AddService(service);
}

void Workspace::RemoveService(const base::UUID& uuid) {
  rpc_manager_->RemoveService(uuid);
}

void Workspace::AddServiceHandler(ServiceHandler* handler) {
  service_handlers_.push_back(handler);
}

void Workspace::RemoveServiceHandler(ServiceHandler* handler) {
  for (auto it = service_handlers_.begin(); it != service_handlers_.end(); it++) {
    if (*it == handler) {
      delete *it;
      service_handlers_.erase(it);
      return;
    }
  }
}

void Workspace::InsertRepo(std::unique_ptr<Repo> repo) {
  repo_manager_->InsertRepo(std::move(repo));
}

void Workspace::RemoveRepo(Repo* repo) {
  repo_manager_->RemoveRepo(repo);
}

void Workspace::RemoveRepo(const base::UUID& uuid) {
  repo_manager_->RemoveRepo(uuid); 
}

  // Channel
void Workspace::InsertChannel(std::unique_ptr<Channel> channel) {
  channel_manager_->InsertChannel(std::move(channel)); 
}

void Workspace::RemoveChannel(Channel* channel) {
  channel_manager_->RemoveChannel(channel); 
}

void Workspace::RemoveChannel(const base::UUID& uuid) {
  channel_manager_->RemoveChannel(uuid); 
}

void Workspace::InstallSchemaAndLibrariesFromVolumeCheckout(Volume* volume, const base::FilePath& path) {
  Bundle* bundle = volume->bundle();
  DCHECK(bundle);
  std::string resources_path = bundle->resources_path();
  std::string executable_path = bundle->application_path();
  InstallSchemaFromVolumeCheckout(volume, path.AppendASCII(resources_path));
  InstallLibrariesFromVolumeCheckout(volume, path.AppendASCII(executable_path));
}

void Workspace::InstallSchemaFromVolumeCheckout(Volume* volume, const base::FilePath& path) {
  base::FilePath schema_path = path.AppendASCII("proto");
  base::FileEnumerator schema_files(schema_path, false, base::FileEnumerator::FILES, FILE_PATH_LITERAL("*.proto"));
  for (base::FilePath schema_file = schema_files.Next(); !schema_file.empty(); schema_file = schema_files.Next()) {
    std::string file_content;
#if defined (OS_WIN)
    std::string file_name = base::UTF16ToASCII(schema_file.RemoveExtension().BaseName().value());
#else
    std::string file_name = schema_file.RemoveExtension().BaseName().value();
#endif
    if (!base::ReadFileToString(schema_file, &file_content)) {
      DLOG(ERROR) << "failed to read schema file content at " << schema_file;
      return;
    }
    // FIXME: this is desirable only for main services.. if theres more than one
    // (a batch service for instance) the injection should not happen
    // BTW, this is a hacky way to insert common methods we will need
    InjectCoreMethods(&file_content);

    std::unique_ptr<Schema> schema = Schema::NewFromProtobuf(schema_registry_.get(), 
      std::move(file_name), 
      std::move(file_content));
    DCHECK(schema);
    schema_registry_->InsertSchema(std::move(schema));
  }
}

void Workspace::InstallLibrariesFromVolumeCheckout(Volume* volume, const base::FilePath& path) {
  base::FilePath exe_path;
  base::PathService::Get(base::DIR_EXE, &exe_path); 

  base::FilePath input_dir = exe_path;
  
#if defined (OS_POSIX)
  base::FilePath input_dev("/dev");
#endif  
  //base::FilePath output_path = path.AppendASCII("lib");
  base::FilePath dev_path = path.AppendASCII("dev");
  if (!base::CreateDirectory(dev_path)) {
    DLOG(ERROR) << "failed to create dev directory " << dev_path;
    return;
  }

  base::FilePath output_path = path.AppendASCII(
    storage::GetIdentifierForArchitecture(storage::GetHostArchitecture()));

  // base::FilePath service_output_path = path.AppendASCII(
  //   storage::GetIdentifierForArchitecture(storage::GetHostArchitecture()));  

std::vector<std::string> dev_access = {
  "urandom"
};


#if defined(COMPONENT_BUILD)
// TODO: this is a nice use-case for the ResourceBundle
  std::vector<std::string> libraries = {
    // "libc++.so",
    // "libapplication_shared.so",
    // "libcommon_shared.so",
    // "libdomain_shared.so",
    // "libbase.so",
    // "libcc.so",
    // "libcc_animation.so",
    // "libcc_paint.so",
    // "libviz_common.so",
    // "libipc.so",
    // "libgpu.so",
    // "libgin.so",
    // "libgles2.so",
    // "libraster.so",
    // "libgles2_implementation.so",
    // "libmedia.so",
    // "libmojo_edk.so",
    // "libbindings.so",
    // "libservice_manager_cpp.so",
    // "libservice_manager_mojom.so",
    // "libtracing_cpp.so",
    // "libnet.so",
    // "libcrcrypto.so",
    // "libskia.so",
    // "libui_base.so",
    // "libui_base_ime.so",
    // "libdisplay.so",
    // "libdisplay_types.so",
    // "libevents.so",
    // "libgesture_detection.so",
    // "libgfx.so",
    // "libanimation.so",
    // "libgeometry.so",
    // "libgl_wrapper.so",
    // "libblink_core.so",
    // "libschemabuf_lite.so",
    // "libv8_libbase.so",
    // "libgfx_x11.so",
    // "libmojo_public_system_cpp.so",
    // "libmojo_public_system.so",
    // "libmojo_cpp_platform.so",
    // "libcolor_space.so",
    // "libgeometry_skia.so",
    // "libcodec.so",
    // "libcrash_key.so",
    // "libmessage_support.so",
    // "libbindings_base.so",
    // "libmojo_mojom_bindings_shared.so",
    // "libgfx_ipc_geometry.so",
    // "liburl.so",
    // "libgl_in_process_context.so",
    // "libshared_memory_support.so",
    // "libgfx_ipc_color.so",
    // "libmojo_base_mojom_shared.so",
    // "libmojo_base_mojom.so",
    // "libmojo_base_lib.so",
    // "libmojo_base_shared_typemap_traits.so",
    // "libbase_i18n.so",
    // "libservice_manager_mojom_constants.so",
    // "libservice_manager_cpp_types.so",
    // "libcc_base.so",
    // "libcc_debug.so",
    // "libmetrics_cpp.so",
    // "libservice.so",
    // "libevents_base.so",
    // "libnetwork_cpp_base.so",
    // "libsandbox.so",
    // "libnetwork_service.so",
    // "libtracing_mojom.so",
    // "libperfetto.so",
    // "libblink_mojo_bindings_shared.so",
    // "libblink_android_mojo_bindings_shared.so",
    // "libwtf.so",
    // "libblink_platform.so",
    // "libgl_init.so",
    // "libprefs.so",
    // "libcapture_base.so",
    // "libfreetype_harfbuzz.so",
    // "libsandbox_services.so",
    // "libbluetooth.so",
    // "libmedia_blink.so",
    // "libclient.so",
    // "libnetwork_cpp.so",
    // "libdiscardable_memory_client.so",
    // "libtracing.so",
    // "libcc_blink.so",
    // "libgfx_switches.so",
    // "libipc_mojom.so",
    // "libmedia_gpu.so",
    // "libblink_common.so",
    // "libmojom_core_shared.so",
    // "libmojom_platform_shared.so",
    // "libgpu_util.so",
    // "libgpu_ipc_service.so",
    // "libcore_shared_common_mojom_shared.so",
    // "libblink_controller.so",
    // "libresource_coordinator_cpp.so",
    // "libresource_coordinator_public_mojom.so",
    // "libv8.so",
    // "libembedder.so",
    // "libhost.so",
    // "libmidi.so",
    // "libnative_theme.so",
    // "libcore_shared_common_mojo_bindings_shared.so",
    // "libgfx_ipc.so",
    // "liburl_ipc.so",
    // "libleveldatabase.so",
    // "libgfx_ipc_skia.so",
    // "libui_base_x.so",
    // "libcc_ipc.so",
    // "libaccessibility.so",
    // "libffmpeg.so",
    // "libviz_resource_format.so",
    // "libmojo_mojom_bindings.so",
    // "libgfx_ipc_buffer_types.so",
    // "libgles2_utils.so",
    // "libkeycodes_x11.so",
    // "libmojo_edk_ports.so",
    // "libservice_manager_mojom_shared.so",
    // "libui_data_pack.so",
    // "libplatform.so",
    // "libdevices.so",
    // "libx11_events_platform.so",
    // "libevents_x.so",
    // "librange.so",
    // "libblink_core_mojo_bindings_shared.so",
    // "libservice_manager_mojom_constants_shared.so",
    // "libcapture_lib.so",
    // "libmedia_mojo_services.so",
    // "libseccomp_bpf.so",
    // "libsuid_sandbox_client.so",
    // "libnetwork_session_configurator.so",
    // "liburl_matcher.so",
    // "libdbus.so",
    // "libsql.so",
    // "libtracing_mojom_shared.so",
    // "libdevice_vr_mojo_bindings_blink.so",
    // "libmojo_base_mojom_blink.so",
    // "libresource_coordinator_public_mojom_blink.so",
    // "libblink_offscreen_canvas_mojo_bindings_shared.so",
    // "libdevice_event_log.so",
    // "libdevice_base.so",
    // "libdiscardable_memory_common.so",
    // "libipc_mojom_shared.so",
    // "libblink_modules.so",
    // "libresource_coordinator_cpp_base.so",
    // "libresource_coordinator_public_mojom_shared.so",
    // "libembedder_switches.so",
    // "libstartup_tracing.so",
    // "libevents_devices_x11.so",
    // "libcdm_manager.so",
    // "libchromium_sqlite3.so",
    // "libdevice_vr_mojo_bindings_shared.so",
    // "libmedia_devices_mojo_bindings_shared.so",
    // "libstorage.so",
    // "libicui18n.so",
    // "libicui18n_swift.so",
    // "libicuuc.so",
    // "libicuuc_swift.so",
    "natives_blob.bin",
    "snapshot_blob.bin",
    "libraries.bin",
    "libraries_extras.bin",
    // "libmumba_kit.so",
    // "libboringssl.so",
    // "libfontconfig.so",
    // "librpc.so",
    // "libgrpc.so",
    "icudtl.dat",
    "icudtl55.dat",
  };
#else
std::vector<std::string> libraries;
// TODO: define at least the main app_sdk dso library
#endif 

  //if (!base::CreateDirectory(output_path)) {
  //  DLOG(ERROR) << "failed to create directory " << output_path;
  //  return;
  //}
  // create links
#if defined(OS_POSIX)
  for (auto it = dev_access.begin(); it != dev_access.end(); ++it) {
    base::CreateSymbolicLink(input_dev.AppendASCII(*it), dev_path.AppendASCII(*it));
  }
  for (auto it = libraries.begin(); it != libraries.end(); ++it) {
    base::CreateSymbolicLink(input_dir.AppendASCII(*it), output_path.AppendASCII(*it));
    //base::CreateSymbolicLink(input_dir.AppendASCII(*it), service_output_path.AppendASCII(*it));
  }
#endif
}

bool Workspace::InstallSchemaFromBundle(std::string filename, int id) {
  ui::ResourceBundle& disk = ui::ResourceBundle::GetSharedInstance();
  base::StringPiece schema_contents = disk.GetRawDataResource(id);
  std::string schema_contents_str;
  // we need to copy as the contents are file mmaped, 
  // and the str thinks it owns the buffer trying to delete it
  // inside the schemabuf code
  base::internal::CopyToString(schema_contents, &schema_contents_str);
  
  if (schema_contents_str.empty()) {
    DLOG(INFO) << "InstallSchemaFromBundle: contents of schema file is empty. id = " << id;
    return false;
  }

//  printf("schema:\n%s\n\n", schema_contents_str.c_str());

  std::unique_ptr<Schema> schema = Schema::NewFromProtobuf(schema_registry_.get(), std::move(filename), std::move(schema_contents_str));
  if (!schema) {
    return false;
  }
  schema_registry_->InsertSchema(std::move(schema), false /* persist */);
  return true;
}

bool Workspace::InstallApplicationFromBundle(const std::string& name, int id) {
  ui::ResourceBundle& disk = ui::ResourceBundle::GetSharedInstance();
  base::StringPiece app_file_contents = disk.GetRawDataResource(id);
  if (app_file_contents.empty()) {
    DLOG(INFO) << "InstallApplicationFromBundle: contents of application file is empty. id = " << id;
    return false;
  }
  // HostThread::PostTask(
  //   HostThread::IO,
  //   FROM_HERE,
  //   base::BindOnce(&Workspace::ExtractZipContentsRaw, 
  //     this, 
  //     name, 
  //     app_file_contents, 
  //     base::Bind(&Workspace::OnInstallApplicationFromBundle, 
  //                this)));

  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(),
      base::WithBaseSyncPrimitives(),
      base::TaskPriority::USER_BLOCKING},
      base::Bind(
        &Workspace::InstallBundleFromContents,
        this,
        name,
        base::Passed(std::move(app_file_contents)),
        base::Bind(&Workspace::OnInstallApplicationFromBundle, 
                   this)));
                 
  return true;
}

void Workspace::OnInstallApplicationFromBundle(std::pair<bool, Volume*> result) {
  if (result.first) {
    CreateDomainFromVolume(result.second, base::Bind(&OnBundleApplicationInstalledFromVolume));
  }
}

Schema* Workspace::GetSchema(const std::string& name) {
  return schema_registry_->model()->GetSchemaByName(name); 
}

void Workspace::InsertSchema(std::unique_ptr<Schema> schema) {
  schema_registry_->InsertSchema(std::move(schema));
}

void Workspace::RemoveSchema(Schema* schema) {
  schema_registry_->RemoveSchema(schema);
}

void Workspace::RemoveSchema(const base::UUID& uuid) {
  schema_registry_->RemoveSchema(uuid);
}

void Workspace::InsertDevice(std::unique_ptr<Device> device) {
  device_manager_->InsertDevice(std::move(device));
}

void Workspace::RemoveDevice(Device* device) {
  device_manager_->RemoveDevice(device);
}

void Workspace::RemoveDevice(const base::UUID& uuid) {
  device_manager_->RemoveDevice(uuid);
}

void Workspace::OnRpcServiceStarted(HostRpcService* service) {
  Schema* schema = service->schema();
  if (schema->package() == "mumba") {
    return;
  }
  Domain* domain = GetDomain(schema->package());
  // there is the system service, that doesnt have a app for it
  if (!domain) {
    DLOG(ERROR) << "BAD. no application host named " << schema->package() 
      << " could be found. Cant add the app data source!";  
    return;
  }
  domain->AddService(service);
  //AddDataSource(domain);
}

void Workspace::OnRpcServiceStopped(HostRpcService* service) {

}

// void Workspace::AddDataSource(Domain* domain) {
//   //DLOG(INFO) << "Workspace::AddDataSources: adding a datasource for '" << domain->name() << "'";
//   RpcDataSource* app_data_source = new RpcDataSource(route_registry_.get(), domain);
//   domain->BindDataSource(app_data_source);
//   URLDataManager::AddDataSource(this, app_data_source);
// }

// void Workspace::AddDataSources() {
//   if (data_sources_added_)
//     return;
//   for (auto it = domain_manager_->apps().begin(); it != domain_manager_->apps().end(); ++it) {
//     Domain* app = it->second;
//     //DLOG(INFO) << "Workspace::AddDataSources: adding a datasource for '" << app->name() << "'";
//     RpcDataSource* app_source = new RpcDataSource(route_registry_.get(), app);
//     app->BindDataSource(app_source);
//     URLDataManager::AddDataSource(this, app_source);
//   }
//   data_sources_added_ = true;
// }

// void Workspace::AddDataSourcesOnIO(URLDataManagerBackend* url_data_manager) {
//   if (data_sources_added_)
//     return;
//   for (auto it = domain_manager_->apps().begin(); it != domain_manager_->apps().end(); ++it) {
//     Domain* app = it->second;
//     //DLOG(INFO) << "Workspace::AddDataSources: adding a datasource for '" << app->name() << "'";
//     URLDataSource* app_source = new RpcDataSource(route_registry_.get(), app);
//     url_data_manager->AddDataSource(app_source);
//   }
//   data_sources_added_ = true;
// }

scoped_refptr<storage::Torrent> Workspace::GetTorrent(const std::string& domain_name, const base::UUID& uuid) const {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->GetTorrent(uuid);
  }
  // not cached or not existant
  if (!storage_manager_->torrent_manager()->HasTorrent(uuid)) {
    storage_manager_->OpenTorrent(domain_name, uuid);
  }
  return storage_manager_->torrent_manager()->GetTorrent(uuid);
}

scoped_refptr<storage::Torrent> Workspace::CreateTorrent(const std::string& domain_name, storage_proto::InfoKind type, const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->CreateTorrent(type, base::UUID::generate(), name, std::move(keyspaces), std::move(cb));
  }
  return storage_manager_->CreateTorrent(domain_name, type, base::UUID::generate(), name, std::move(keyspaces), std::move(cb));
}

scoped_refptr<storage::Torrent> Workspace::CreateTorrent(const std::string& domain_name, storage_proto::InfoKind type, const base::UUID& uuid, const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->CreateTorrent(type, uuid, name, std::move(keyspaces), std::move(cb));
  }
  return storage_manager_->CreateTorrent(domain_name, type, uuid, name, std::move(keyspaces), std::move(cb));
}

scoped_refptr<storage::Torrent> Workspace::OpenTorrent(const std::string& domain_name, const base::UUID& uuid, base::Callback<void(int64_t)> cb) {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->OpenTorrent(uuid, std::move(cb));
  }
  if (!storage_manager_->torrent_manager()->HasTorrent(uuid)) {
     storage_manager_->OpenTorrent(domain_name, uuid, std::move(cb));
  }
  return storage_manager_->torrent_manager()->GetTorrent(uuid);
}

scoped_refptr<storage::Torrent> Workspace::OpenTorrent(const std::string& domain_name, const std::string& name, base::Callback<void(int64_t)> cb) {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->OpenTorrent(name, std::move(cb));
  }
  storage_manager_->OpenTorrent(domain_name, name, std::move(cb));
  return storage_manager_->GetTorrent(domain_name, name);
}
  
bool Workspace::DeleteTorrent(const std::string& domain_name, const std::string& name) {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->DeleteTorrent(name);
  }
  return storage_manager_->DeleteTorrent(domain_name, name);
}

bool Workspace::DeleteTorrent(const std::string& domain_name, const base::UUID& uuid) {
  if (domain_name == storage_->workspace_disk_name()) {
    return storage_->DeleteTorrent(uuid);
  }
  return storage_manager_->DeleteTorrent(domain_name, uuid);
}

scoped_refptr<ShareDatabase> Workspace::GetDatabase(const base::UUID& uuid) {
  // see if its cached as a share already
  Share* share = share_manager_->GetShare(uuid);
  if (share) {
    return share->db();
  }
  scoped_refptr<storage::Torrent> torrent = storage_manager_->torrent_manager()->GetTorrent(uuid);
  share = share_manager_->CreateShare(torrent);
  return share->db();
}

scoped_refptr<ShareDatabase> Workspace::GetDatabase(const std::string& name) {
  // see if its cached as a share already
  Share* share = share_manager_->GetShare(workspace_storage()->workspace_disk_name(), name);
  if (share) {
    return share->db();
  }
  // if not create a share cache and returns the database from it
  // the share manager owns the share, so is safe to pass the share database
  // as parent object lifetime is garanteed 
  scoped_refptr<storage::Torrent> torrent = storage_manager_->GetTorrent(workspace_storage()->workspace_disk_name(), name);
  share = share_manager_->CreateShare(torrent);
  return share->db(); 
}

scoped_refptr<ShareDatabase> Workspace::CreateDatabase(const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  scoped_refptr<storage::Torrent> torrent = CreateTorrent(workspace_storage()->workspace_disk_name(), storage_proto::INFO_DATA, name, keyspaces, std::move(cb));
  Share* share = share_manager_->CreateShare(torrent);
  return share->db();
}

scoped_refptr<ShareDatabase> Workspace::OpenDatabase(const base::UUID& uuid, base::Callback<void(int64_t)> cb) {
  Share* share = share_manager_->GetShare(workspace_storage()->workspace_disk_name(), uuid);
  if (share) {
    std::move(cb).Run(net::OK);
    return share->db();
  }
  scoped_refptr<storage::Torrent> torrent = OpenTorrent(workspace_storage()->workspace_disk_name(), uuid, std::move(cb));
  share = share_manager_->CreateShare(torrent);
  return share->db();
}

scoped_refptr<ShareDatabase> Workspace::OpenDatabase(const std::string& name, base::Callback<void(int64_t)> cb) {
  Share* share = share_manager_->GetShare(workspace_storage()->workspace_disk_name(), name);
  if (share) {
    std::move(cb).Run(net::OK);
    return share->db();
  }
  scoped_refptr<storage::Torrent> torrent = OpenTorrent(workspace_storage()->workspace_disk_name(), name, std::move(cb));
  share = share_manager_->CreateShare(torrent);
  return share->db();
}

bool Workspace::DeleteDatabase(const base::UUID& uuid) {
  //return DeleteTorrent(workspace_storage()->workspace_disk_name(), uuid);
  return share_manager_->DropShare(workspace_storage()->workspace_disk_name(), uuid);
}

bool Workspace::DeleteDatabase(const std::string& name) {
  //return DeleteTorrent(workspace_storage()->workspace_disk_name(), name);
  return share_manager_->DropShare(workspace_storage()->workspace_disk_name(), name);
}

void Workspace::OpenDatabaseSync(const base::UUID& uuid) {
  storage_->OpenDatabaseSync(uuid);
}

scoped_refptr<net::IOBufferWithSize> Workspace::Serialize() const {
  return protocol::SerializeMessage(workspace_schema_); 
}

void Workspace::SetDatabasePolicy(DatabasePolicy policy) {
  bool changed = policy != db_policy_;
  db_policy_ = policy;
  if (changed) {
    for (auto* obs : db_policy_observers_) {
      obs->OnDatabasePolicyChanged(policy);
    }
  }
}

void Workspace::OnVolumeManagerInitError() {
  DLOG(ERROR) << "workspace '" << name() << "': volume manager initialization error";
}

void Workspace::OnVolumeManagerInitCompleted() {
  //DLOG(INFO) << "workspace '" << name() << "': volume manager initialization done";
}

Schema* Workspace::ResolveSchemaForService(const std::string& container, const std::string& service_name) {
  return schema_registry_->model()->GetSchemaWithService(container, service_name);
}

// void Workspace::PopulateRouteRegistryWithSystem() {
//   DLOG(INFO) << "PopulateRouteRegistryWithSystem";
//   workspace_service_dispatcher_->InstallSchemaFromBundle();
//   Schema* schema = schema_registry_->model()->GetSchemaByName("mumba");
//   DCHECK(schema);
//   const google::schemabuf::ServiceDescriptor* descriptor = schema->GetServiceDescriptorNamed("MumbaManager");
//   DCHECK(descriptor);
//   for (int i = 0; i < descriptor->method_count(); ++i) {
//     const google::schemabuf::MethodDescriptor* method = descriptor->method(i);
//     std::string name = method->full_name();//base::ToLowerASCII(method->name());
//     DLOG(INFO) << "PopulateRouteRegistryWithSystem: adding '" << name << "' as method entry";
//     common::mojom::RoutePtr entry = common::mojom::Route::New();
//     entry->name = name;
//     entry->type = common::mojom::RouteType::kURL_ENTRY_TYPE_METHOD;
//     entry->url = GURL("mumba://" + name);
//     entry->path = "/" + name;
//     route_registry_->AddEntry(std::move(entry));
//   }
// }

void Workspace::InitializeWorkspaceServices() {
  if (!workspace_service_dispatcher_->Init()) {
    DLOG(ERROR) << "Workspace: error initializing workspace services";
  }
}

void Workspace::OnStorageManagerInit(IOThread* io_thread, DatabasePolicy db_policy, int result) {
  if (initializing_) {
    return;
  }
  if (result == net::OK) {
    // We are on the main thread here, so we need to dispatch
    // to some blocking io thread
    // base::PostTaskWithTraits(
    //   FROM_HERE,
    //   {base::MayBlock(), base::WithBaseSyncPrimitives() },
    //   base::BindOnce(&Workspace::InitializeStorageImpl,
    //    base::Unretained(this), 
    //    base::Unretained(io_thread),
    //    db_policy)); 
    InitializeStorageImpl(io_thread, db_policy);
  } else {
    DLOG(ERROR) << "storage manager initialization failed";
    // this is a dead end error, so we need to shutdown everything
    // and stop the main loop
    scoped_refptr<HostController> controller = HostController::Instance();
    controller->ShutdownHost();
  }
}

void Workspace::InitializeStorageImpl(IOThread* io_thread, DatabasePolicy db_policy) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  initializing_ = true;
  
  //storage::Storage* workspace_storage = nullptr;
  if (!storage_->Init(storage_manager_.get(), base::Bind(&Workspace::CreateOrOpenSystemDatabases, this))) {
    DLOG(ERROR) << "Workspace initialization failed: storage init on workspace '" << name() << "'";
    return;
  }
}

void Workspace::CreateOrOpenSystemDatabases(int64_t result) {
  
  if (result != net::OK) {
    DLOG(ERROR) << "Workspace initialization failed: error initialing workspace storage";
    return;
  }

  if (first_time_) {
    //workspace_storage = storage_manager_->GetStorage(storage_->workspace_disk());
    //if (!workspace_storage) {
    //  DLOG(ERROR) << "Workspace initialization failed: failed to create storage for workspace '"<< name() <<"'";
    //  return;
    //}
    //DLOG(INFO) << "Workspace initialization (" << this << "): first time. creating system database..";
    std::vector<std::string> keyspaces = GetSystemKeyspaces();
    storage_manager_->CreateTorrent(
      storage_->workspace_disk_name(), 
      storage_proto::INFO_DATA, 
      "system", 
      std::move(keyspaces), 
      base::Bind(&Workspace::OnSystemDatabaseInit, this, base::Unretained(io_thread_), db_policy()));
  } else {
    //workspace_storage = storage_manager_->GetStorage(storage_->workspace_disk());
    //if (!workspace_storage) {
    //  DLOG(ERROR) << "Workspace initialization failed: failed to load storage for workspace '"<< name() <<"'";
    //  return;
    //}
    //DLOG(INFO) << "Workspace initialization (" << this << "): opening system database..";
    storage_manager_->OpenTorrent(
      storage_->workspace_disk_name(), 
      "system", 
      base::Bind(&Workspace::OnSystemDatabaseInit, this, base::Unretained(io_thread_), db_policy()));
  }
}

void Workspace::OnSystemDatabaseInit(IOThread* io_thread, DatabasePolicy db_policy, int64_t result) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //DLOG(INFO) << "Workspace::OnSystemDatabaseInit (" << this << "): database system initialize: r = " << result;
  if (result == net::OK) {
    base::UUID id;
    bool ok = storage_manager_->GetUUID(storage_->workspace_disk_name(), "system", &id);
    if (!ok) {
      DLOG(ERROR) << "Workspace initialization failed: no system db on workspace '" << name() << "'";
      return;
    }

    // base::PostTaskWithTraits(
    //    FROM_HERE,
    //    { base::MayBlock(),
    //      base::WithBaseSyncPrimitives(),
    //      base::TaskPriority::USER_BLOCKING},
    //      base::Bind(
    //        &Workspace::InitializeDatabases,
    //        base::Unretained(this),
    //        base::Unretained(io_thread),
    //        id,
    //        db_policy));
    if (!HostThread::CurrentlyOn(HostThread::UI)) {
      HostThread::PostTask(
        HostThread::UI, 
        FROM_HERE, 
        base::BindOnce(
          &Workspace::InitializeDatabases,
          this,
          base::Unretained(io_thread),
          id,
          db_policy));
    } else {
      InitializeDatabases(io_thread, id, db_policy);
    }
  } else {
    DLOG(ERROR) << "Workspace initialization: database system init failed";    
  }
}

void Workspace::InitializeDatabases(IOThread* io_thread, const base::UUID& id, DatabasePolicy db_policy) {
  // TODO: we need to wrap the 'system' torrent into a consistent shared database
  // we can just provide the database api, but with the awareness of some sync logic
  // (example: if its using open/close and two concurrent threads try to open the db handle
  //  at the same time.. we need to process one and delay the other.. its the same on close)
  scoped_refptr<storage::Torrent> system_db_torrent = storage_manager_->torrent_manager()->GetTorrent(id);
  DCHECK(system_db_torrent);
  // create the share that wraps the system torrent
  std::unique_ptr<Share> system_share = std::make_unique<Share>(share_manager_.get(), storage_->workspace_disk_name(), system_db_torrent, std::vector<std::string>(), false);
  scoped_refptr<ShareDatabase> system_db = system_share->db();

  device_manager_->Init();
  bundle_manager_->Init(system_db, db_policy_);
  volume_manager_->Init(system_db, db_policy_, storage_manager_.get(), bundle_manager_.get()); 
  identity_manager_->Init(system_db, db_policy_);
  rpc_manager_->Init();
  route_registry_->Init();
  domain_manager_->Init(
    system_db,
    db_policy_, 
    root_path(), 
    io_thread);
  schema_registry_->Init(system_db, db_policy_, root_path());
  repo_manager_->Init(system_db, db_policy_);
  channel_manager_->Init(system_db, db_policy_);
  share_manager_->Init(std::move(system_share), db_policy_);

  //Share* system_graph = share_manager_->CreateShare(storage_->workspace_disk_name(), "system_graph", true /* in_memory*/);
  //scoped_refptr<ShareDatabase> system_graph_db = system_graph->db();
  //DCHECK(system_graph_db);
  
// Disable financial system(stellar) for now
//  market_manager_->Init();

  // initialize window manager on UI
  //HostThread::PostTask(
  //  HostThread::UI,
  //  FROM_HERE,
  //  base::Bind(&Workspace::WindowManagerInitializeOnUI, 
  //    base::Unretained(this)));

  db_policy_observers_.push_back(volume_manager_->volumes());
  db_policy_observers_.push_back(volume_manager_->sources());
  db_policy_observers_.push_back(identity_manager_->identities());
  db_policy_observers_.push_back(domain_manager_->model());
  db_policy_observers_.push_back(schema_registry_->model());
  db_policy_observers_.push_back(channel_manager_->channels());
  db_policy_observers_.push_back(repo_manager_->model());

  if (db_policy == DatabasePolicy::OpenClose) {
    system_db->Close();
  }

  SetDatabasePolicy(db_policy);

  //PopulateRouteRegistryWithSystem();
  
  InitializeWorkspaceServices();

  if (!volume_storage()->storage_manager()->GetStorage("world")) {
    base::FilePath world_path;
    base::PathService::Get(base::DIR_ASSETS, &world_path); 
    base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(),
      base::WithBaseSyncPrimitives(),
      base::TaskPriority::USER_BLOCKING},
      base::Bind(
        &Workspace::InstallBundle,
        this,
        "world",
        world_path.AppendASCII("world.bundle"),
        base::Bind(&Workspace::OnInstallApplicationFromBundle, 
                   this)));
    //InstallApplicationFromBundle("world", IDR_WORLD_APP);
  } //else {
  //  DLOG(INFO) << "world already installed, so doing nothing";
  //}

  initialized_ = true;
  initializing_ = false;
  
  //DLOG(INFO) << "Workspace initialization done ok";
}

void Workspace::OnVolumeAddedAsEntry(storage::Storage* volume_storage, Bundle* bundle, base::Callback<void(std::pair<bool, Volume*>)> callback, bool sync, int64_t result) {
  DCHECK(volume_storage);
  if (result == 0) {
    sync ? 
      volume_manager_->InstallVolumeSync(volume_storage, bundle, std::move(callback)) : 
      volume_manager_->InstallVolume(volume_storage, bundle, std::move(callback));
  } else {
    DLOG(ERROR) << "error while adding container to the storage";
    std::move(callback).Run(std::make_pair(false, nullptr));
  }
}

void Workspace::OnVolumeCloned(const std::string& dht_address_hex, base::Callback<void(std::pair<bool, Volume*>)> callback, bool sync, int result) {
  //DLOG(INFO) << "\n\n\n\nWorkspace::OnVolumeCloned: r = " << result << "\n\n\n\n";
  if (result == 0) {
    //DLOG(INFO) << "Workspace::OnVolumeCloned: OK";
    storage::StorageManager* manager = volume_storage()->storage_manager();
    storage::Storage* volume_storage = manager->GetStorageByDHTAddress(dht_address_hex);
    // fixme: this probably wont work as bundle wont be added
    //        we need to install the bundle from the cloned storage 
    //        and only then add as volume 
    Bundle* bundle = bundle_manager_->GetBundle(volume_storage->name());
    DCHECK(volume_storage);
    DCHECK(bundle);
    sync ? 
      volume_manager_->InstallVolumeSync(volume_storage, bundle, std::move(callback)) : 
      volume_manager_->InstallVolume(volume_storage, bundle, std::move(callback));
  } else {
    DLOG(INFO) << "Workspace::OnVolumeCloned: FAILED";
  }
}

void Workspace::InstallBundle(const std::string& name,
                            const base::FilePath& path, 
                            base::Callback<void(std::pair<bool, Volume*>)> callback) {
  base::FilePath out_path = bundle_manager_->GetOutputPath();
  bundle_manager_->UnpackBundleImpl(
    name, 
    path,
    out_path,
    base::BindOnce(&Workspace::OnBundleInstalled, 
                  this,
                  path, 
                  out_path,
                  base::Passed(std::move(callback))));
}

void Workspace::InstallBundleFromContents(const std::string& name,
                                        const base::StringPiece contents, 
                                        base::Callback<void(std::pair<bool, Volume*>)> callback) {
  base::ScopedAllowBlockingForTesting scoped_allow;
  base::FilePath out_path = bundle_manager_->GetOutputPath();
  bundle_manager_->UnpackBundleFromContentsImpl(
    name, 
    contents,
    out_path,
    base::BindOnce(&Workspace::OnBundleInstalledWithName, 
                    this,
                    name, 
                    out_path,
                    base::Passed(std::move(callback))));
}

void Workspace::OnBundleInstalled(const base::FilePath& input_path,
                                const base::FilePath& output_path, 
                                base::Callback<void(std::pair<bool, Volume*>)> callback,
                                bool result) {
  if (!result) {
    DLOG(ERROR) << "error: failed while installing bundle from '" << input_path << "'. install cancelled";
    return;
  }

#if defined (OS_WIN)
  std::string app_name = base::UTF16ToASCII(input_path.BaseName().RemoveExtension().value());
#else
  std::string app_name = input_path.BaseName().RemoveExtension().value();
#endif
  OnBundleInstalledWithName(app_name, output_path, std::move(callback), result);
}

void Workspace::OnBundleInstalledWithName(const std::string& app_name,
                                        const base::FilePath& output_path, 
                                        base::Callback<void(std::pair<bool, Volume*>)> callback,
                                        bool result) {
  // call it again, now with the extracted directory as input
  InstallVolume(output_path, app_name, std::move(callback), true);
}

void Workspace::OnApplicationsLoad(int r, int count) {
  if (r == net::OK) {
    DomainModel::Domains& domain_list = domain_manager_->GetDomains();
    for (auto it = domain_list.begin(); it != domain_list.end(); ++it) {
      Domain* domain = it->second;
      //if (!window_manager_domain_ && shell->IsWindowHostDomain()) {
      //  window_manager_domain_ = shell;
      //}
      if (!domain->main_volume()) {
        Volume* volume = volume_manager()->volumes()->GetVolumeByName(domain->name());
        DCHECK(volume);
        domain->AddVolume(volume, true /* is_main */);
      }
      if (domain->ShouldLaunchOnInit()) {
        LaunchDomain(domain, base::Callback<void(int)>());
      }
    }
    for (auto& observer : observers_) {
      observer.OnApplicationsLoaded(count);
    }
    //printf("apps loaded: %d\n", count);
  }
}

void Workspace::OnDomainAdded(Domain* app) {
  for (auto& observer : observers_) {
    observer.OnApplicationCreated(app);
  }
}

void Workspace::OnDomainRemoved(Domain* app) {
  for (auto& observer : observers_) {
    observer.OnApplicationDestroyed(app);
  }
}

void Workspace::OnDomainLaunched(Domain* app) {}

void Workspace::OnDomainShutdown(Domain* app) {}

void Workspace::OnDevicesLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnDevicesLoaded(count);
    }
    //printf("devices loaded: %d\n", count);
  }
}

void Workspace::OnDeviceAdded(Device* device) {
  for (auto& observer : observers_) {
    observer.OnDeviceCreated(device);
  }
}

void Workspace::OnDeviceRemoved(Device* device) {
  for (auto& observer : observers_) {
    observer.OnDeviceDestroyed(device);
  }
}

void Workspace::OnChannelsLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnChannelsLoaded(count);
    }
    //printf("channels loaded: %d\n", count);
  }
}

void Workspace::OnChannelAdded(Channel* channel) {
  for (auto& observer : observers_) {
    observer.OnChannelCreated(channel);
  }
}

void Workspace::OnChannelRemoved(Channel* channel) {
  for (auto& observer : observers_) {
    observer.OnChannelDestroyed(channel);
  }
}

void Workspace::OnIdentitiesLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnIdentitiesLoaded(count);
    }
    //printf("identities loaded: %d\n", count);
  }
}
void Workspace::OnIdentityAdded(Identity* id) {
  for (auto& observer : observers_) {
    observer.OnIdentityCreated(id);
  }
}

void Workspace::OnIdentityRemoved(Identity* id) {
  for (auto& observer : observers_) {
    observer.OnIdentityDestroyed(id);
  }
}

void Workspace::OnReposLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnReposLoaded(count);
    }
    //printf("repos loaded: %d\n", count);
  }
}
void Workspace::OnRepoAdded(Repo* repo) {
  for (auto& observer : observers_) {
    observer.OnRepoCreated(repo);
  }
}

void Workspace::OnRepoRemoved(Repo* repo) {
  for (auto& observer : observers_) {
    observer.OnRepoDestroyed(repo);
  }
}

void Workspace::OnServicesLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnServicesLoaded(count);
    }
    //printf("services loaded: %d\n", count);
  }
}
void Workspace::OnServiceAdded(HostRpcService* service) {
  for (auto& observer : observers_) {
    observer.OnServiceCreated(service);
  }
}

void Workspace::OnServiceRemoved(HostRpcService* service) {
  for (auto& observer : observers_) {
    observer.OnServiceDestroyed(service);
  }
}

void Workspace::OnSchemasLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnSchemasLoaded(count);
    }
    //printf("schemas loaded: %d\n", count);
  }
}

void Workspace::OnSchemaAdded(Schema* schema) {
  for (auto& observer : observers_) {
    observer.OnSchemaCreated(schema);
  }
}

void Workspace::OnSchemaRemoved(Schema* schema) {
  for (auto& observer : observers_) {
    observer.OnSchemaDestroyed(schema);
  }
}

void Workspace::OnRouteEntriesLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnRoutesLoaded(count);
    }
    //printf("portals loaded: %d\n", count);
  }
}
void Workspace::OnRouteAdded(RouteEntry* entry) {
  for (auto& observer : observers_) {
    observer.OnRouteCreated(entry);
  }
}

void Workspace::OnRouteRemoved(RouteEntry* entry) {
  for (auto& observer : observers_) {
    observer.OnRouteDestroyed(entry);
  }
}

void Workspace::OnVolumesLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnVolumesLoaded(count);
    }
    //printf("volumes loaded: %d\n", count);
  }
}

void Workspace::OnVolumeAdded(Volume* volume) {
  for (auto& observer : observers_) {
    observer.OnVolumeCreated(volume);
  }
}

void Workspace::OnVolumeRemoved(Volume* volume) {
  for (auto& observer : observers_) {
    observer.OnVolumeDestroyed(volume);
  }
}

void Workspace::OnBundlesLoad(int r, int count) {
  if (r == net::OK) {
    for (auto& observer : observers_) {
      observer.OnBundlesLoaded(count);
    }
    printf("bundles loaded: %d\n", count);
  }
}

void Workspace::OnBundleAdded(Bundle* bundle) {
  for (auto& observer : observers_) {
    observer.OnBundleAdded(bundle);
  }
}

void Workspace::OnBundleRemoved(Bundle* bundle) {
  for (auto& observer : observers_) {
    observer.OnBundleRemoved(bundle);
  }
}

void Workspace::OnDockAdded(Dock* dock) {
  dock->tablist_model()->AddObserver(this);
}
void Workspace::OnDockClosing(Dock* dock) {}
void Workspace::OnDockRemoved(Dock* dock) {}
void Workspace::OnDockSetLastActive(Dock* dock) {}
void Workspace::OnDockNoLongerActive(Dock* dock) {}

void Workspace::TabInsertedAt(TablistModel* tablist_model, ApplicationContents* contents, int index, bool foreground) {}
void Workspace::TabClosingAt(TablistModel* tablist_model, ApplicationContents* contents, int index) {}
void Workspace::TabDetachedAt(ApplicationContents* contents, int index) {}
void Workspace::TabDeactivated(ApplicationContents* contents) {}
void Workspace::ActiveTabChanged(ApplicationContents* old_contents, ApplicationContents* new_contents,int index, int reason) {}
void Workspace::TabSelectionChanged(TablistModel* tablist_model, const ui::ListSelectionModel& old_model) {}
void Workspace::TabMoved(ApplicationContents* contents, int from_index, int to_index) {}
void Workspace::TabChangedAt(ApplicationContents* contents, int index, TabChangeType change_type) {}
void Workspace::TabReplacedAt(TablistModel* tablist_model, ApplicationContents* old_contents, ApplicationContents* new_contents, int index) {}
void Workspace::TabPinnedStateChanged(TablistModel* tablist_model, ApplicationContents* contents, int index) {}
void Workspace::TabBlockedStateChanged(ApplicationContents* contents, int index) {}
void Workspace::TablistEmpty() {}
void Workspace::WillCloseAllTabs() {}
void Workspace::CloseAllTabsCanceled() {}
void Workspace::SetTabNeedsAttentionAt(int index, bool attention) {}

void Workspace::InjectCoreMethods(std::string* proto) const {
  proto->append("\n\n");
  proto->append(kCoreServices);
}


}
