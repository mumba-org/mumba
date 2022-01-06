// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_CONTEXT_H_
#define MUMBA_DOMAIN_DOMAIN_CONTEXT_H_

#include <memory>
#include <unordered_map>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/uuid.h"
#include "core/domain/domain_thread.h"
#include "core/shared/domain/storage/storage_manager.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/shared/common/mojom/repo.mojom.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace IPC {
class SyncChannel;  
}

namespace blink {
class AssociatedInterfaceRegistry;
}

namespace common {
class ServiceManagerConnection;  
}

namespace domain {
class DomainMainThread;
class DeviceManager;
class ModuleLoader;
class ModuleDispatcher;
class DeviceDispatcher;
class WindowManagerClient;
class ApplicationManagerClient;
class StorageDispatcher;
class IdentityManagerClient;
class ServiceDispatcher;
class LauncherClient;
class P2PSocketDispatcher;
class ApplicationManager;
class RouteDispatcher;

enum class DomainState {
  kUndefined,
  kBootstrap, // bootstrap mode: creating the needed backend infra
  kStarted,
  kStopped,
  kExiting
};

struct DomainInfo {
  std::string name;
  std::string version;
  DomainState state = DomainState::kUndefined;
};

class DomainContext : public base::RefCountedThreadSafe<DomainContext>,
                       public StorageManager::Delegate {
public:
  DomainContext(
    DomainMainThread* main_thread,
    const base::FilePath& domain_root,
    const base::UUID& domain_id,
    const std::string& domain_name);

  DomainState state() const { return info_.state; }
  const std::string& name() const { return name_; }
  const std::string& version() const { return info_.version; }
  const DomainInfo& info() const { return info_; }

  StorageManager* storage_manager() const { return storage_manager_.get(); }
  DeviceManager* device_manager() const { return device_manager_.get(); }
  ModuleLoader* module_loader() const { return module_loader_.get(); }
  ApplicationManager* application_manager() { return application_manager_.get(); }

  StorageDispatcher* storage_dispatcher() const { return storage_dispatcher_.get(); }
  ModuleDispatcher* module_dispatcher() const { return module_dispatcher_.get(); }
  DeviceDispatcher* device_dispatcher() const { return device_dispatcher_.get(); }
  WindowManagerClient* window_manager_client() const { return window_manager_client_.get(); }
  ApplicationManagerClient* application_manager_client() const { return application_manager_client_.get(); }
  IdentityManagerClient* identity_manager_client() const { return identity_manager_client_.get(); }
  LauncherClient* launcher_client() const { return launcher_client_.get(); }
  ServiceDispatcher* service_dispatcher() const { return service_dispatcher_.get(); }
  RouteDispatcher* route_dispatcher() const { return route_dispatcher_.get(); }
  common::mojom::RouteRegistry* GetRouteRegistry();
  common::mojom::ServiceRegistry* GetServiceRegistry();
  common::mojom::ChannelRegistry* GetChannelRegistry();
  common::mojom::ApplicationManagerHost* GetApplicationManagerHost();
  common::ServiceManagerConnection* GetServiceManagerConnection();

  bool Init(
    P2PSocketDispatcher* p2p_socket_dispatcher, 
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    IPC::SyncChannel* ipc_channel,
    blink::AssociatedInterfaceRegistry* associated_interface_registry);

  void Shutdown();


private:
  friend class base::RefCountedThreadSafe<DomainContext>;
  friend class DomainMainThread;

  ~DomainContext();

  // Delegate

  void OnStorageManagerInit(bool result) override;
  //void OnContextCreated(scoped_refptr<StorageContext> context);
  //void OnModuleAvailable(scoped_refptr<StorageContext> context);
  void LoadModules();
 
  DomainMainThread* main_thread_;
  base::FilePath domain_root_;
  std::string name_;
  base::UUID id_;

  std::unique_ptr<StorageDispatcher> storage_dispatcher_;
  std::unique_ptr<ModuleDispatcher> module_dispatcher_;
  std::unique_ptr<DeviceDispatcher> device_dispatcher_;
  std::unique_ptr<WindowManagerClient> window_manager_client_;
  std::unique_ptr<ApplicationManagerClient> application_manager_client_;
  std::unique_ptr<IdentityManagerClient> identity_manager_client_;
  std::unique_ptr<ServiceDispatcher> service_dispatcher_;
  std::unique_ptr<RouteDispatcher> route_dispatcher_;
  std::unique_ptr<LauncherClient> launcher_client_;

  std::unique_ptr<StorageManager> storage_manager_;
  std::unique_ptr<DeviceManager> device_manager_;
  std::unique_ptr<ModuleLoader> module_loader_;
  std::unique_ptr<ApplicationManager> application_manager_;
  common::mojom::RouteRegistryAssociatedPtr domain_registry_interface_;
  common::mojom::ChannelRegistryAssociatedPtr channel_registry_interface_;
  common::mojom::ServiceRegistryAssociatedPtr service_registry_interface_;

  DomainInfo info_;

  DISALLOW_COPY_AND_ASSIGN(DomainContext);
};

}

#endif