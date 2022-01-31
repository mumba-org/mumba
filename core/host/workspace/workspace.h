// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_WORKSPACE_H_
#define MUMBA_HOST_WORKSPACE_WORKSPACE_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "base/observer_list.h"
#include "base/synchronization/lock.h"
#include "base/supports_user_data.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/host_controller.h"
#include "core/host/application/domain_manager.h"
#include "core/host/application/domain_model.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "net/rpc/rpc.h"
#include "core/host/workspace/workspace_storage.h"
#include "core/host/workspace/workspace_observer.h"
#include "core/host/serializable.h"
#include "core/host/database_policy.h"
#include "core/host/themes/theme_service.h"
#include "core/host/device/device_manager.h"
#include "core/host/channel/channel_manager_observer.h"
#include "core/host/bundle/bundle_manager_observer.h"
#include "core/host/identity/identity_manager.h"
#include "core/host/repo/repo_manager_observer.h"
#include "core/host/collection/collection_observer.h"
#include "core/host/rpc/server/rpc_manager.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/route/route_observer.h"
#include "core/host/volume/volume_manager.h"
#include "storage/proto/storage.pb.h"
#include "core/host/ui/dock_list_observer.h"
#include "core/host/ui/tablist/tablist_model_observer.h"

namespace storage {
class Database;
class StorageManager;
}

namespace host {
class WorkspaceStorage;
class Schema;
class IOThread;
class ServiceHandler;
class WorkspaceServiceDispatcher;
class StorageManager;
class Identity;
class ThemeService;
class AppStorage;
class ResourceContextImpl;
class ServiceRegistry;
class RouteRegistry;
class RouteResolver;
class Repo;
class RepoManager;
class RepoRegistry;
class Device;
class Channel;
class ChannelManager;
class ApplicationController;
class MLModelManager;
class MLServiceManager;
class MLModelServiceDispatcher;
class MLPredictionServiceDispatcher;
class MLController;
class RunnableManager;
class ShareManager;
class ShareRegistry;
class APIManager;
class APIDispatcher;
class MarketDispatcher;
class MarketManager;
class BundleManager;
class Bundle;
class CollectionDispatcher;
class Collection;

struct WorkspaceParams {
  base::FilePath profile_path;
  std::string workspace_name = "default";
  std::string admin_service_host = "127.0.0.1";
  int admin_service_port = 27761;
};

class Workspace : public Serializable,
                  public VolumeManager::Delegate,
                  public DomainManager::Observer,
                  public DeviceManager::Observer,
                  public IdentityManager::Observer,
                  public RepoManagerObserver, 
                  public RpcManager::Observer,
                  public SchemaRegistry::Observer,
                  public RouteObserver,
                  public VolumeManager::Observer,
                  public DockListObserver,
                  public BundleManagerObserver,
                  public ChannelManagerObserver,
                  public TablistModelObserver,
                  public CollectionObserver,
                  public base::RefCountedThreadSafe<Workspace> {
public:
  // TODO: We need to bind this with a 'workspace disk' now
  // creating the disk first and then 'bootstraping' the 
  // workspace from there

  static scoped_refptr<Workspace> New(const std::string& name);
  static scoped_refptr<Workspace> GetCurrent();
  static scoped_refptr<Workspace> Deserialize(net::IOBuffer* buffer, int size);
  
  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const {
    return workspace_schema_.name();
  }

  bool is_current() const {
    return current_;
  }

  void set_current(bool current) {
    current_ = current;
  }

  bool is_first_time() const {
    return first_time_;
  }

  const base::FilePath& root_path() const;
 
  VolumeManager* volume_manager() const { 
    return volume_manager_.get(); 
  }

  IdentityManager* identity_manager() const { 
    return identity_manager_.get(); 
  }

  DomainManager* domain_manager() const { 
    return domain_manager_.get(); 
  }

  DeviceManager* device_manager() const { 
    return device_manager_.get(); 
  }

  SchemaRegistry* schema_registry() const { 
    return schema_registry_.get(); 
  }

  RpcManager* rpc_manager() const { 
    return rpc_manager_.get(); 
  }

  ThemeService* theme_service() const {
    return theme_service_.get();
  }

  RouteRegistry* route_registry() const {
    return route_registry_.get();
  }

  RouteResolver* route_resolver() const {
    return route_resolver_.get();
  }

  ServiceRegistry* service_registry() const {
    return service_registry_.get();
  }

  ChannelManager* channel_manager() const {
    return channel_manager_.get();
  }

  RepoManager* repo_manager() const {
    return repo_manager_.get();
  }

  RepoRegistry* repo_registry() const {
    return repo_registry_.get();
  }

  ApplicationController* application_controller() const {
    return application_controller_.get();
  }

  MLModelManager* ml_model_manager() const {
    return ml_model_manager_.get();
  }

  MLServiceManager* ml_service_manager() const {
    return ml_service_manager_.get();
  }
  
  MLPredictionServiceDispatcher* ml_prediction_service_dispatcher() const {
    return ml_prediction_service_dispatcher_.get();
  }

  MLModelServiceDispatcher* ml_model_service_dispatcher() const {
    return ml_model_service_dispatcher_.get();
  }

  MLController* ml_controller() const {
    return ml_controller_.get();
  }

  RunnableManager* runnable_manager() const {
    return runnable_manager_.get();
  }

  ShareRegistry* share_registry() const {
    return share_registry_.get();
  }

  ShareManager* share_manager() const {
    return share_manager_.get();
  }

  APIManager* api_manager() const {
    return api_manager_.get(); 
  }

  APIDispatcher* api_dispatcher() const {
    return api_dispatcher_.get();  
  }

  MarketDispatcher* market_dispatcher() const {
    return market_dispatcher_.get();
  }

  MarketManager* market_manager() const {
    return market_manager_.get(); 
  }

  BundleManager* bundle_manager() const {
    return bundle_manager_.get();
  }

  Collection* collection() const {
    return collection_.get();
  }

  CollectionDispatcher* collection_dispatcher() const {
    return collection_dispatcher_.get();
  }

  int generate_next_application_id();

  void set_theme_service(std::unique_ptr<ThemeService> service) {
    theme_service_ = std::move(service);
  }

  storage::StorageManager const* storage_manager() const {
    return storage_manager_.get();
  }

  storage::StorageManager& storage_manager() {
    base::AutoLock m(storage_manager_lock_);
    return *storage_manager_;
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& domain_socket_acceptor() const {
    return domain_socket_acceptor_;
  }

  VolumeStorage* volume_storage();
  AppStorage* app_storage();
  WorkspaceStorage* workspace_storage() const {
    return storage_.get();
  }

  const base::FilePath& volume_dir() const;
  const base::FilePath& app_dir() const;
  const base::FilePath& tmp_dir() const;
  IOThread* io_thread() const {
    return io_thread_;
  }

  bool Init(
    const WorkspaceParams& params,
    IOThread* io_thread, 
    const scoped_refptr<HostController>& controller,
    DatabasePolicy db_policy);
  
  void Shutdown();

  DatabasePolicy db_policy() const { return db_policy_; }
  void SetDatabasePolicy(DatabasePolicy policy);

  // Domain api 
  bool HasDomain(const std::string& name) const;
  bool HasDomainUUID(const std::string& uuid) const;
  bool HasDomain(const base::UUID& uuid) const;
  bool HasDomain(const common::DomainInfo& info) const;
  bool HasDomain(const GURL& url) const;
  Domain* GetDomain(const std::string& name) const;
  Domain* GetDomain(const base::UUID& uuid) const;
  Domain* GetDomain(const GURL& url) const;
  Domain* GetDomain(const common::DomainInfo& info) const;
  const DomainModel::Domains& GetDomains() const;
  DomainModel::Domains& GetDomains();
  void CreateDomainFromVolume(Volume* volume, base::Callback<void(int)> cb);
  void CheckoutVolume(Volume* volume, const base::UUID& domain_id, base::Callback<void(int)> cb);
  void CreateDomain(std::unique_ptr<Domain> domain, base::Callback<void(int)> cb);
  void DestroyDomain(const std::string& name);
  void DestroyDomain(const base::UUID& uuid);
  void LaunchDomain(const base::UUID& uuid, base::Callback<void(int)> callback);
  void LaunchDomain(const std::string& name, base::Callback<void(int)> callback);
  void LaunchDomain(Domain* shell, base::Callback<void(int)> callback);
  void ShutdownDomain(const std::string& name, base::Callback<void(int)> callback);

  base::FilePath GetApplicationRootPath(const std::string& domain_name);
  base::FilePath GetApplicationExecutablePath(const std::string& domain_name);

  // Volume api
  void AddVolume(storage::Storage* volume_storage, const base::Callback<void(std::pair<bool, base::UUID>)>& callback);
  bool IsVolumeInstalled(const base::UUID& id);
  void InstallVolume(
    const base::FilePath& path, 
    base::Callback<void(std::pair<bool, Volume*>)> callback,
    bool sync);
  void InstallVolume(
    const base::FilePath& path, 
    const std::string& disk_name,
    base::Callback<void(std::pair<bool, Volume*>)> callback,
    bool sync);
  void InstallVolume(
    const base::StringPiece zip_contents, 
    const std::string& disk_name,
    base::Callback<void(std::pair<bool, Volume*>)> callback,
    bool sync);
  void InstallVolumeSync(const base::FilePath& path, 
    base::Callback<void(std::pair<bool, Volume*>)> callback);
  void InstallVolumeFromDHTAddressSync(
    const std::string& dht_address_hex, 
    base::Callback<void(std::pair<bool, Volume*>)> callback);  
  void InsertVolume(Volume* volume);
  void RemoveVolume(Volume* volume);

  // Rpc api
  HostRpcService* CreateService(
    //Domain* shell,
    const std::string& volume,
    const std::string& service_name,
    const std::string& host,
    int port, 
    net::RpcTransportType type,
    scoped_refptr<base::SingleThreadTaskRunner> main_runner,
    std::unique_ptr<net::RpcHandler> rpc_handler);
  
  HostRpcService* GetService(const base::UUID& uuid) const;
  HostRpcService* GetService(const std::string& name) const;
  void AddService(HostRpcService* service);
  void RemoveService(const base::UUID& uuid);

  // Schema api
  void InstallSchemaAndLibrariesFromVolumeCheckout(Volume* volume, const base::FilePath& path);
  void InstallSchemaFromVolumeCheckout(Volume* volume, const base::FilePath& path);
  void InstallLibrariesFromVolumeCheckout(Volume* volume, const base::FilePath& path);
  bool InstallSchemaFromBundle(std::string filename, int id);
  bool InstallApplicationFromBundle(const std::string& name, int id);
  Schema* GetSchema(const std::string& name);
  void InsertSchema(std::unique_ptr<Schema> schema);
  void RemoveSchema(Schema* schema);
  void RemoveSchema(const base::UUID& uuid);

  // Identity
  void InsertIdentity(std::unique_ptr<Identity> identity);
  void RemoveIdentity(Identity* identity);
  void RemoveIdentity(const base::UUID& uuid);

  // Repo
  void InsertRepo(std::unique_ptr<Repo> repo);
  void RemoveRepo(Repo* repo);
  void RemoveRepo(const base::UUID& uuid);

  // Channel
  void InsertChannel(std::unique_ptr<Channel> channel);
  void RemoveChannel(Channel* channel);
  void RemoveChannel(const base::UUID& uuid);

  // Device
  void InsertDevice(std::unique_ptr<Device> device);
  void RemoveDevice(Device* device);
  void RemoveDevice(const base::UUID& uuid);

  // Torrents
  scoped_refptr<storage::Torrent> GetTorrent(const std::string& domain_name, const base::UUID& uuid) const;
  scoped_refptr<storage::Torrent> CreateTorrent(const std::string& domain_name, storage_proto::InfoKind type, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<storage::Torrent> CreateTorrent(const std::string& domain_name, storage_proto::InfoKind type, const base::UUID& uuid, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<storage::Torrent> OpenTorrent(const std::string& domain_name, const base::UUID& uuid, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<storage::Torrent> OpenTorrent(const std::string& domain_name, const std::string& name, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  bool DeleteTorrent(const std::string& domain_name, const base::UUID& uuid);
  bool DeleteTorrent(const std::string& domain_name, const std::string& name);
  
  void OpenDatabaseSync(const base::UUID& uuid);

  //void AddDataSource(Domain* domain);  
  //void AddDataSources();
  //void AddDataSourcesOnIO(URLDataManagerBackend* url_data_manager);
  // UI Host
//  void LaunchUIHost();

  // Handlers
  const std::vector<ServiceHandler *>& service_handlers() const {
    return service_handlers_;
  }

  void AddServiceHandler(ServiceHandler* handler);
  void RemoveServiceHandler(ServiceHandler* handler);

  scoped_refptr<net::IOBufferWithSize> Serialize() const;

  // VolumeManagerDelegate
  VolumeStorage* GetVolumeStorage() override {
    return volume_storage();
  }

  void AddObserver(WorkspaceObserver* observer) {
    observers_.AddObserver(observer);
  }

  void RemoveObserver(WorkspaceObserver* observer) {
    observers_.RemoveObserver(observer);
  }

private:
  friend class RpcManager;
  friend class base::RefCountedThreadSafe<Workspace>;

  Workspace(protocol::Workspace workspace_schema);
  Workspace(const std::string& name);

  ~Workspace() override;

  void OnVolumeManagerInitError() override;
  void OnVolumeManagerInitCompleted() override;

  void OnRpcServiceStarted(HostRpcService* service);
  void OnRpcServiceStopped(HostRpcService* service);

  void OnVolumeAddedAsEntry(
    storage::Storage* volume_storage,
    Bundle* bundle,
    base::Callback<void(std::pair<bool, Volume*>)> callback,
    bool sync,
    int64_t result);

  void OnVolumeCloned(
    const std::string& address, 
    base::Callback<void(std::pair<bool, Volume*>)> callback, 
    bool sync, 
    int result);

  // ApplicationHostManager observer
  void OnApplicationsLoad(int r, int count) override;
  void OnDomainAdded(Domain* app) override;
  void OnDomainRemoved(Domain* app) override;
  void OnDomainLaunched(Domain* app) override;
  void OnDomainShutdown(Domain* app) override;

  // DeviceManagerObserver
  void OnDevicesLoad(int r, int count) override;
  void OnDeviceAdded(Device* device) override;
  void OnDeviceRemoved(Device* device) override;

  // ChannelManagerObserver
  void OnChannelsLoad(int r, int count) override;
  void OnChannelAdded(Channel* channel) override;
  void OnChannelRemoved(Channel* channel) override;

  // IdentityManagerObserver
  void OnIdentitiesLoad(int r, int count) override;
  void OnIdentityAdded(Identity* id) override;
  void OnIdentityRemoved(Identity* id) override;
  
  // RepoManagerObserver
  void OnReposLoad(int r, int count) override;
  void OnRepoAdded(Repo* repo) override;
  void OnRepoRemoved(Repo* repo) override;

  // RpcServiceManagerObserver
  void OnServicesLoad(int r, int count) override;
  void OnServiceAdded(HostRpcService* service) override;
  void OnServiceRemoved(HostRpcService* service) override;
  
  // SchemaManagerObserver
  void OnSchemasLoad(int r, int count) override;
  void OnSchemaAdded(Schema* schema) override;
  void OnSchemaRemoved(Schema* schema) override;

  //RouteObserver
  void OnRouteEntriesLoad(int r, int count) override;
  void OnRouteAdded(RouteEntry* entry) override;
  void OnRouteRemoved(RouteEntry* entry) override;

  // VolumeManagerObserver
  void OnVolumesLoad(int r, int count) override;
  void OnVolumeAdded(Volume* volume) override;
  void OnVolumeRemoved(Volume* volume) override;

  // BundleManagerObserver
  void OnBundlesLoad(int r, int count) override;
  void OnBundleAdded(Bundle* bundle) override;
  void OnBundleRemoved(Bundle* bundle) override;

  // CollectionObserver
  void OnCollectionEntriesLoad(int r, int count) override;
  void OnCollectionEntryAdded(CollectionEntry* entry) override;
  void OnCollectionEntryRemoved(CollectionEntry* entry) override;

  // DockListObserver
  void OnDockAdded(Dock* dock) override;
  void OnDockClosing(Dock* dock) override;
  void OnDockRemoved(Dock* dock) override;
  void OnDockSetLastActive(Dock* dock) override;
  void OnDockNoLongerActive(Dock* dock) override;

  // TablistModelObserver
  void TabInsertedAt(TablistModel* tablist_model,
                     ApplicationContents* contents,
                     int index,
                     bool foreground) override;
  void TabClosingAt(TablistModel* tablist_model,
                    ApplicationContents* contents,
                    int index) override;
  void TabDetachedAt(ApplicationContents* contents, int index) override;
  void TabDeactivated(ApplicationContents* contents) override;
  void ActiveTabChanged(ApplicationContents* old_contents,
                        ApplicationContents* new_contents,
                        int index,
                        int reason) override;
  void TabSelectionChanged(TablistModel* tablist_model,
                           const ui::ListSelectionModel& old_model);
  void TabMoved(ApplicationContents* contents,
                           int from_index,
                           int to_index) override;
  void TabChangedAt(ApplicationContents* contents,
                    int index,
                    TabChangeType change_type) override;
  void TabReplacedAt(TablistModel* tablist_model,
                     ApplicationContents* old_contents,
                     ApplicationContents* new_contents,
                     int index) override;
  void TabPinnedStateChanged(TablistModel* tablist_model,
                             ApplicationContents* contents,
                             int index) override;
  void TabBlockedStateChanged(ApplicationContents* contents,
                              int index) override;
  void TablistEmpty() override;
  void WillCloseAllTabs() override;
  void CloseAllTabsCanceled() override;
  void SetTabNeedsAttentionAt(int index, bool attention) override;

  void OnStorageManagerInit(IOThread* io_thread, DatabasePolicy db_policy, int result);

  Schema* ResolveSchemaForService(const std::string& volume, const std::string& service_name);
  //void PopulatePlaceRegistryWithSystem();
  void InitializeWorkspaceServices();

  //void WindowManagerInitializeOnUI();
  void OnSystemDatabaseInit(IOThread* io_thread, DatabasePolicy db_policy, int64_t result);
  void InitializeDatabases(IOThread* io_thread, const base::UUID& id, DatabasePolicy db_policy);
  void InitializeStorageImpl(IOThread* io_thread, DatabasePolicy db_policy);
  void CreateOrOpenSystemDatabases(int64_t result);
  void OnVolumeCheckout(Volume* volume, const base::UUID& domain_id, const base::FilePath& path, base::Callback<void(int)> cb, int64_t result);
  void OnVolumeStorageCreated(
    const base::FilePath& path, 
    const std::string& disk_name,
    Bundle* bundle,
    base::Callback<void(std::pair<bool, Volume*>)> callback,
    bool sync,
    storage::Storage* storage, 
    int result);
  void InstallBundle(const std::string& name,
                   const base::FilePath& path, 
                   base::Callback<void(std::pair<bool, Volume*>)> callback);

  void InstallBundleFromContents(const std::string& name,
                               const base::StringPiece zip_contents, 
                               base::Callback<void(std::pair<bool, Volume*>)> callback);

  void OnBundleInstalled(const base::FilePath& input_path,
                              const base::FilePath& output_path, 
                              base::Callback<void(std::pair<bool, Volume*>)> callback,
                              bool result);

  void OnBundleInstalledWithName(const std::string& app_name,
                                      const base::FilePath& output_path, 
                                      base::Callback<void(std::pair<bool, Volume*>)> callback,
                                      bool result);

  void OnInstallApplicationFromBundle(std::pair<bool, Volume*> result);
  
  scoped_refptr<ShareDatabase> GetDatabase(const base::UUID& uuid);
  scoped_refptr<ShareDatabase> GetDatabase(const std::string& name);
  scoped_refptr<ShareDatabase> CreateDatabase(const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<ShareDatabase> OpenDatabase(const base::UUID& uuid, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<ShareDatabase> OpenDatabase(const std::string& name, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  bool DeleteDatabase(const base::UUID& uuid);
  bool DeleteDatabase(const std::string& name);

  protocol::Workspace workspace_schema_;

  base::UUID id_;

  bool current_;
  bool initializing_;
  bool initialized_;
  bool first_time_;
  bool data_sources_added_;

  int next_application_id_;

  DatabasePolicy db_policy_;
  base::Lock storage_manager_lock_;

  //std::unique_ptr<WindowManager> window_manager_;
  IOThread* io_thread_;
  std::unique_ptr<WorkspaceStorage> storage_;
  std::unique_ptr<VolumeManager> volume_manager_;
  std::unique_ptr<IdentityManager> identity_manager_;
  std::unique_ptr<DomainManager> domain_manager_;
  std::unique_ptr<DeviceManager> device_manager_;
  std::unique_ptr<SchemaRegistry> schema_registry_;
  std::unique_ptr<RouteRegistry> route_registry_;
  std::unique_ptr<RouteResolver> route_resolver_;
  std::unique_ptr<ServiceRegistry> service_registry_;
  std::unique_ptr<RpcManager> rpc_manager_;
  std::unique_ptr<storage::StorageManager> storage_manager_;
  std::unique_ptr<StorageManager> storage_context_manager_;
  std::unique_ptr<ThemeService> theme_service_;
  std::unique_ptr<RepoManager> repo_manager_;
  std::unique_ptr<RepoRegistry> repo_registry_;
  std::unique_ptr<ChannelManager> channel_manager_;
  std::unique_ptr<ApplicationController> application_controller_;
  std::unique_ptr<MLModelManager> ml_model_manager_;
  std::unique_ptr<MLServiceManager> ml_service_manager_;
  std::unique_ptr<MLModelServiceDispatcher> ml_model_service_dispatcher_;
  std::unique_ptr<MLPredictionServiceDispatcher> ml_prediction_service_dispatcher_;
  std::unique_ptr<MLController> ml_controller_;
  std::unique_ptr<RunnableManager> runnable_manager_;
  std::unique_ptr<ShareRegistry> share_registry_;
  std::unique_ptr<ShareManager> share_manager_;
  std::unique_ptr<APIManager> api_manager_;
  std::unique_ptr<APIDispatcher> api_dispatcher_;
  std::unique_ptr<MarketDispatcher> market_dispatcher_;
  std::unique_ptr<MarketManager> market_manager_;
  std::unique_ptr<BundleManager> bundle_manager_;
  std::unique_ptr<Collection> collection_;
  std::unique_ptr<CollectionDispatcher> collection_dispatcher_;
   
  scoped_refptr<base::SingleThreadTaskRunner> domain_socket_acceptor_;
  
  std::vector<DatabasePolicyObserver *> db_policy_observers_;

  std::unique_ptr<WorkspaceServiceDispatcher> workspace_service_dispatcher_;

  std::vector<ServiceHandler *> service_handlers_;

  base::ObserverList<WorkspaceObserver> observers_;
  
  DISALLOW_COPY_AND_ASSIGN(Workspace);
};

}

#endif