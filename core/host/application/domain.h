// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_H_

#include <memory>
#include <map>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/serializable.h"
#include "core/host/application/domain_process_host.h"
#include "core/common/proto/objects.pb.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/host/appcache/chrome_appcache_service.h"
#include "core/host/background_sync/background_sync_context.h"
#include "core/host/blob_storage/blob_url_loader_factory.h"
//#include "content/browser/bluetooth/bluetooth_allowed_devices_map.h"
#include "core/host/broadcast_channel/broadcast_channel_provider.h"
#include "core/host/cache_storage/cache_storage_context_impl.h"
//#include "content/browser/dom_storage/dom_storage_context_wrapper.h"
//#include "core/host/indexed_db/indexed_db_context_impl.h"
//#include "content/browser/locks/lock_manager.h"
#include "core/host/notifications/platform_notification_context_impl.h"
//#include "content/browser/payments/payment_app_context_impl.h"
//#include "content/browser/push_messaging/push_messaging_context.h"
#include "core/host/application/offscreen_canvas_provider_impl.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_type.h"
#include "core/host/shared_worker/shared_worker_service_impl.h"
#include "core/host/url_loader_factory_getter.h"
#include "core/host/ui/dock.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "storage/host/blob/blob_registry_impl.h"
#include "storage/host/blob/blob_storage_context.h"
#include "storage/host/database/database_tracker.h"
#include "storage/host/quota/quota_manager.h"
#include "ui/base/window_open_disposition.h"

using ApplicationReplyCallback = base::OnceCallback<void(::common::mojom::ApplicationStatus)>;

namespace storage {
class Storage;  
}

namespace net {
class RpcService;  
}

namespace service_manager {
class Connector;
}

namespace host {
class Schema;
class RpcDataSource;
class Application;
class ApplicationManagerHost;
class DomainProcessHost;
class Volume;
class HostRpcService;
class Workspace;
class ApplicationProcessHost;
class BackgroundFetchDelegate;
class BackgroundSyncController;
class ChromeBlobStorageContext;
class PlatformNotificationContextImpl;
class BackgroundFetchContext;
class BlobRegistryWrapper;
class BlobURLLoaderFactory;
class StreamContext;
class ResourceContextImpl;
class CacheStorageContextImpl;
class URLLoaderFactoryGetter;
class PrefetchURLLoaderService;
class FileURLLoaderFactory;
class IpcURLLoaderFactory;
class ServiceWorkerDispatcherHost;
class DomainAutomationHost;
class RunnableManager;
class RouteDispatcherClient;
class Bundle;
// A managed domain

class Domain : public DomainProcessHost::Observer,
               public Serializable {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnApplicationLaunched(Domain* domain, Application* application) {}
    virtual void OnApplicationInitialized(Domain* domain, Application* application) {}
    virtual void OnApplicationShutdown(Domain* domain, Application* application) {}
    virtual void OnDomainServiceAdd(Domain* domain, HostRpcService* service) {}
    virtual void OnDomainServiceRemove(Domain* domain, HostRpcService* service) {}
  };

  static char kClassName[];

  static std::unique_ptr<Domain> New(scoped_refptr<Workspace> workspace, const base::UUID& id, const std::string& name, const base::UUID& volume_id);
  static std::unique_ptr<Domain> Deserialize(scoped_refptr<Workspace> workspace, net::IOBuffer* buffer, int size);

  ~Domain() override;

  const std::string& name() const {
    return domain_proto_.name();
  }

  const base::UUID& id() const {
    return id_;
  }

  const base::UUID& container_id() const {
    return container_id_;
  }

  const base::FilePath& partition_path() const {
    return partition_path_;
  }

  RunnableManager* runnable_manager() const {
    return runnable_manager_;
  }

  void Init();
  void InitOnIO();

  DomainProcessHost* process() {
    return raw_process_;
  }

  void BindProcess(DomainProcessHost* process);

  service_manager::Connector* GetConnector() const;

  ApplicationManagerHost* host_manager() const {
    return host_manager_.get();
  }

  const std::vector<HostRpcService*>& services() const {
    return services_;
  }

  const std::vector<Volume*>& volumes() const {
    return volumes_;
  }

  RpcDataSource* data_source() const {
    return data_source_;
  }

  Bundle* bundle() const;

  Volume* main_volume() const {
    return main_volume_;
  }

  scoped_refptr<Workspace> workspace() const;

  DomainAutomationHost* automation_host() const {
    return automation_host_.get();
  }

  const base::WeakPtr<DomainProcessHost>& process_for_io() {
    DCHECK_CURRENTLY_ON(HostThread::IO);
    if (!process_io_weak_ptr_ && raw_process_) {
      process_io_weak_ptr_ = raw_process_->GetWeakPtrForIO();
    }
    return process_io_weak_ptr_;
  }

  void BindDataSource(RpcDataSource* data_source) {
    data_source_ = data_source;
  }

  void AddVolume(Volume* volume, bool is_main = false) {
    if (main_volume_ == nullptr && is_main) {
      main_volume_ = volume;
    }
    volumes_.push_back(volume);
  }

  void RemoveVolume(Volume* volume) {
    for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
      if ((*it) == volume) {
        volumes_.erase(it);
        return;
      }
    }
  }

  void AddService(HostRpcService* service) {
    services_.push_back(service);
    NotifyServiceAdded(service);
  }

  void RemoveService(HostRpcService* service) {
    for (auto it = services_.begin(); it != services_.end(); ++it) {
      if ((*it) == service) {
        services_.erase(it);
        NotifyServiceRemoved(service);
        return;
      }
    } 
  }

  // for now its fixed to true, but we need to specify the real conditions
  // for this to be true, as we use this check to launch the shell
  // right on the host process initialization
  // (this must be a flag on the database)
  bool ShouldLaunchOnInit() const;

  bool IsRunning() const {
    return raw_process_ != nullptr && online_;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

  // managed = persisted on DB
  bool IsManaged() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  
  Application* NewApplication(int id, 
    const std::string& name, 
    const GURL& url, 
    const base::UUID& uuid, 
    Dock::Type window_mode,
    gfx::Rect initial_bounds,
    WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless);

  std::vector<Runnable*> runnables() const;
  Runnable* GetRunnable(int id) const;
  bool HaveRunnable(int id) const;

  Application* GetApplication(int id) const;
  bool HaveApplication(int id) const;
  
  void Shutdown(base::Callback<void(int)> callback, bool host_shutdown = false);

  // listener for application process events bounded to this app host
  void OnApplicationLaunched(Application* application);
  void OnApplicationInitialized(Application* application);
  void OnApplicationShutdownRequested(Application* application);
  void OnApplicationWillExit(Application* application);
  void OnApplicationProcessExited(Application* application,
                                  ApplicationProcessHost* process,
                                  const ChildProcessTerminationInfo& info);
  void OnApplicationProcessDestroyed(Application* application,
                                     ApplicationProcessHost* process);

  void OnDomainProcessLaunched(DomainProcessHost* host);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);
  bool HaveObserver(Observer* observer);

  BackgroundFetchDelegate* GetBackgroundFetchDelegate();
  BackgroundSyncController* GetBackgroundSyncController();
  ChromeBlobStorageContext* GetBlobStorageContext();
  void SetBlobStorageContext(scoped_refptr<ChromeBlobStorageContext> blob_context);
  PlatformNotificationContextImpl* GetPlatformNotificationContext();
  scoped_refptr<ServiceWorkerContextWrapper> GetServiceWorkerContext();
  StreamContext* GetStreamContext();
  void SetStreamContext(const scoped_refptr<StreamContext>& context);
  ResourceContextImpl* GetResourceContext() const {
    return resource_context_.get();
  }
  CacheStorageContextImpl* GetCacheStorageContext();
  BlobURLLoaderFactory* GetBlobURLLoaderFactory();
  FileURLLoaderFactory* GetFileURLLoaderFactory();
  net::URLRequestContextGetter* GetURLRequestContext();
  void SetURLRequestContext(net::URLRequestContextGetter* url_request_context);
  net::URLRequestContextGetter* GetMediaURLRequestContext();
  void SetMediaURLRequestContext(net::URLRequestContextGetter* media_url_request_context);
  ChromeAppCacheService* GetAppCacheService();
  storage::FileSystemContext* GetFileSystemContext();
  PrefetchURLLoaderService* GetPrefetchURLLoaderService();
  BroadcastChannelProvider* GetBroadcastChannelProvider();
  SharedWorkerServiceImpl* GetSharedWorkerService();
  BlobRegistryWrapper* GetBlobRegistry();
  RouteDispatcherClient* GetRouteDispatcherClient() const;
  scoped_refptr<URLLoaderFactoryGetter> url_loader_factory_getter() const {
    return url_loader_factory_getter_;
  }

  ServiceWorkerProcessType GetServiceWorkerProcessType() const;
  int GetServiceWorkerProcessId(int application_process_id = -1) const;
  scoped_refptr<ServiceWorkerDispatcherHost> GetServiceWorkerDispatcherHostForApplication(int application_process_id) const;

  void CreateOffscreenCanvasProvider(
    blink::mojom::OffscreenCanvasProviderRequest request);

private:
  friend class DomainProcessHost;

  Domain(scoped_refptr<Workspace> workspace, protocol::Domain domain_info);
  Domain(scoped_refptr<Workspace> workspace);

  // Observer
  void DomainProcessReady(DomainProcessHost* host) override;
  void DomainProcessShutdownRequested(DomainProcessHost* host) override;
  void DomainProcessWillExit(DomainProcessHost* host) override;
  void DomainProcessExited(DomainProcessHost* host,
                                   const ChildProcessTerminationInfo& info) override;
  void DomainProcessHostDestroyed(DomainProcessHost* host) override;

  void RemoveApplication(Application* app);

  void ProcessShutdownOnIO(DomainProcessHost* process, base::Callback<void(int)> callback);

  void OnVolumeShutdown(base::Callback<void(int)> callback, int64_t result);
  void OnDomainProcessShutdown(base::Callback<void(int)> callback, int code);

  void NotifyApplicationLaunched(Application* app);
  void NotifyApplicationInitialized(Application* app);
  void NotifyApplicationShutdown(Application* app);
  void NotifyServiceAdded(HostRpcService* service);
  void NotifyServiceRemoved(HostRpcService* service);

  void GetQuotaSettings(
    storage::OptionalQuotaSettingsCallback callback);

  scoped_refptr<Workspace> workspace_;

  RunnableManager* runnable_manager_;

  base::UUID id_;

  base::UUID container_id_;

  base::FilePath partition_path_;

  protocol::Domain domain_proto_;

  // TODO: this deserves a WeakPtr
  DomainProcessHost* raw_process_;

  base::WeakPtr<DomainProcessHost> process_ui_weak_ptr_;
  // weak ptr, but for io thread
  base::WeakPtr<DomainProcessHost> process_io_weak_ptr_;

  std::unique_ptr<DomainAutomationHost> automation_host_;

  RpcDataSource* data_source_;

  Volume* main_volume_;

  std::unique_ptr<ApplicationManagerHost> host_manager_;

  std::vector<HostRpcService* > services_;

  std::vector<Volume*> volumes_;

  std::map<int, std::string> mailbox_;

  //std::vector<std::unique_ptr<Application>> applications_;

  std::vector<Observer *> observers_;

  scoped_refptr<ChromeBlobStorageContext> blob_storage_context_;
  scoped_refptr<PlatformNotificationContextImpl> platform_notification_context_;
  scoped_refptr<storage::QuotaManager> quota_manager_;
  scoped_refptr<ChromeAppCacheService> appcache_service_;
  scoped_refptr<storage::FileSystemContext> filesystem_context_;
  scoped_refptr<storage::DatabaseTracker> database_tracker_;
  //scoped_refptr<IndexedDBContextImpl> indexed_db_context_;
  scoped_refptr<CacheStorageContextImpl> cache_storage_context_;
  scoped_refptr<ServiceWorkerContextWrapper> service_worker_context_;
  std::unique_ptr<SharedWorkerServiceImpl> shared_worker_service_;
 // scoped_refptr<PushMessagingContext> push_messaging_context_;
 // scoped_refptr<storage::SpecialStoragePolicy> special_storage_policy_;
//  std::unique_ptr<WebPackageContextImpl> web_package_context_;
  scoped_refptr<BackgroundFetchContext> background_fetch_context_;
  scoped_refptr<BackgroundSyncContext> background_sync_context_;
  //scoped_refptr<PaymentAppContextImpl> payment_app_context_;
  scoped_refptr<BroadcastChannelProvider> broadcast_channel_provider_;
//  scoped_refptr<BluetoothAllowedDevicesMap> bluetooth_allowed_devices_map_;
  scoped_refptr<URLLoaderFactoryGetter> url_loader_factory_getter_;
  scoped_refptr<net::URLRequestContextGetter> url_request_context_;
  scoped_refptr<net::URLRequestContextGetter> media_url_request_context_;
  scoped_refptr<BlobURLLoaderFactory> blob_url_loader_factory_;
  std::unique_ptr<FileURLLoaderFactory> file_factory_;
  scoped_refptr<BlobRegistryWrapper> blob_registry_;
  scoped_refptr<PrefetchURLLoaderService> prefetch_url_loader_service_;
  scoped_refptr<StreamContext> stream_context_;
  std::unique_ptr<ResourceContextImpl, HostThread::DeleteOnIOThread> resource_context_;
  scoped_refptr<ServiceWorkerDispatcherHost> service_worker_worker_dispatcher_host_;
  std::unique_ptr<OffscreenCanvasProviderImpl> offscreen_canvas_provider_;
  std::unique_ptr<RouteDispatcherClient> route_dispatcher_client_;

  bool managed_;

  bool online_;

  bool shutting_down_;

  bool wait_for_application_shutdown_;

  ServiceWorkerProcessType service_worker_process_type_;

  base::AtomicSequenceNumber mailbox_id_;

  base::WaitableEvent done_;

  base::WeakPtrFactory<Domain> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(Domain);
};

}

#endif