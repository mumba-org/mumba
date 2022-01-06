// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/service_registry.h"

#include "core/host/workspace/workspace.h"
#include "core/host/workspace/workspace_storage.h"
#include "core/host/rpc/server/rpc_manager.h"

namespace host {

ServiceRegistry::ServiceRegistry(scoped_refptr<Workspace> workspace): 
  workspace_(workspace),
  rpc_manager_(workspace->rpc_manager()),
  shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED) {
}

ServiceRegistry::~ServiceRegistry() {

}

void ServiceRegistry::AddBinding(common::mojom::ServiceRegistryAssociatedRequest request) {
  service_registry_binding_.AddBinding(this, std::move(request));
}

void ServiceRegistry::Shutdown() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ServiceRegistry::ShutdownImpl, 
      base::Unretained(this)));
  shutdown_event_.Wait();
}

void ServiceRegistry::ShutdownImpl() {
  for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
    it->second.second.reset();
  }
  service_registry_binding_.CloseAllBindings();
  shutdown_event_.Signal();
}

void ServiceRegistry::LookupService(const std::string& scheme, const std::string& name, LookupServiceCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::LookupServiceImpl, 
      base::Unretained(this),
      scheme,
      name,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::LookupServiceImpl(const std::string& scheme, const std::string& name, LookupServiceCallback callback) {
  HostRpcService* service = rpc_manager_->GetService(name);
  if (!service) {
    DLOG(INFO) << "ServiceRegistry: service '" << name << "' not found";
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::ServiceStatusCode::kSERVICE_STATUS_ERR_ENTRY_NOT_FOUND,
        nullptr));
    return;
  }
  common::mojom::ServiceEntryPtr entry = common::mojom::ServiceEntry::New();
  entry->scheme = service->container();
  entry->name = service->name();
  entry->uuid = service->uuid().to_string();
  //entry->host = service->host();
  //entry->port = service->port();
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::ServiceStatusCode::kSERVICE_STATUS_OK,
        base::Passed(std::move(entry))));
}

void ServiceRegistry::LookupServiceByUUID(const std::string& uuid, LookupServiceByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::LookupServiceByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::LookupServiceByUUIDImpl(const std::string& uuid, LookupServiceByUUIDCallback callback) {
  bool ok = false;
  base::UUID real_uuid = base::UUID::from_string(uuid, &ok);
  if (!ok) {
    DLOG(INFO) << "ServiceRegistry: service " << uuid << " is invalid";
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::ServiceStatusCode::kSERVICE_STATUS_ERR_ENTRY_NOT_FOUND,
        nullptr));
    return;
  }
  HostRpcService* service = rpc_manager_->GetService(real_uuid);
  if (!service) {
    DLOG(INFO) << "ServiceRegistry: service " << uuid << " not found";
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::ServiceStatusCode::kSERVICE_STATUS_ERR_ENTRY_NOT_FOUND,
        nullptr));
    return;
  }
  common::mojom::ServiceEntryPtr entry = common::mojom::ServiceEntry::New();
  entry->scheme = service->container();
  entry->name = service->name();
  entry->uuid = service->uuid().to_string();
  //entry->host = service->host();
  //entry->port = service->port();
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::ServiceStatusCode::kSERVICE_STATUS_OK,
        base::Passed(std::move(entry))));
}

void ServiceRegistry::HaveService(const std::string& scheme, const std::string& name, HaveServiceCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::HaveServiceImpl, 
      base::Unretained(this),
      scheme,
      name,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::HaveServiceImpl(const std::string& scheme, const std::string& name, HaveServiceCallback callback) {
  bool found = rpc_manager_->GetService(name);
  HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        found));
}

void ServiceRegistry::HaveServiceByUUID(const std::string& uuid, HaveServiceByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::HaveServiceByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::HaveServiceByUUIDImpl(const std::string& uuid, HaveServiceByUUIDCallback callback) {
  bool ok = false;
  base::UUID real_uuid = base::UUID::from_string(uuid, &ok);
  if (!ok) {
    DLOG(INFO) << "ServiceRegistry: service " << uuid << " is invalid";
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        false));
    return;
  }
  bool found = rpc_manager_->HaveService(real_uuid);
  HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        found));
}

void ServiceRegistry::ListServices(ListServicesCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::ListServicesImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void ServiceRegistry::ListServicesImpl(ListServicesCallback callback) {
  std::vector<common::mojom::ServiceEntryPtr> entries;
  const std::unordered_map<base::UUID, HostRpcService *>& services = rpc_manager_->services();
  for (auto it = services.begin(); it != services.end(); ++it) {
    HostRpcService* service = it->second;
    common::mojom::ServiceEntryPtr entry = common::mojom::ServiceEntry::New();
    entry->scheme = service->container();
    entry->name = service->name();
    entry->uuid = service->uuid().to_string();
    //entry->host = service->host();
    //entry->port = service->port();
    entries.push_back(std::move(entry));
  }
  HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        base::Passed(std::move(entries))));
}

void ServiceRegistry::ListServicesForScheme(const std::string& scheme, ListServicesForSchemeCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::ListServicesForSchemeImpl, 
      base::Unretained(this),
      scheme,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::ListServicesForSchemeImpl(const std::string& scheme, ListServicesForSchemeCallback callback) {
  std::vector<common::mojom::ServiceEntryPtr> entries;
  const std::unordered_map<base::UUID, HostRpcService *>& services = rpc_manager_->services();
  for (auto it = services.begin(); it != services.end(); ++it) {
    HostRpcService* service = it->second;
    if (service->container() == scheme) {
      common::mojom::ServiceEntryPtr entry = common::mojom::ServiceEntry::New();
      entry->scheme = service->container();
      entry->name = service->name();
      entry->uuid = service->uuid().to_string();
      //entry->host = service->host();
      //entry->port = service->port();
      entries.push_back(std::move(entry));
    }
  }
  HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        base::Passed(std::move(entries))));
}

void ServiceRegistry::GetServiceHeader(const std::string& url, GetServiceHeaderCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::GetServiceHeaderImpl, 
      base::Unretained(this),
      url,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::GetServiceHeaderImpl(const std::string& url, GetServiceHeaderCallback callback) {

}

void ServiceRegistry::GetServiceCount(GetServiceCountCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::GetServiceCountImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void ServiceRegistry::GetServiceCountImpl(GetServiceCountCallback callback) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      rpc_manager_->services().size()));
}

void ServiceRegistry::StartService(const std::string& uuid, StartServiceCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::StartServiceImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::StartServiceImpl(const std::string& uuid, StartServiceCallback callback) {

}

void ServiceRegistry::StopService(const std::string& uuid, StopServiceCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::StopServiceImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void ServiceRegistry::StopServiceImpl(const std::string& uuid, StopServiceCallback callback) {

}

void ServiceRegistry::Subscribe(const std::string& scheme, common::mojom::ServiceSubscriberPtr subscriber, SubscribeCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::SubscribeImpl, 
      base::Unretained(this),
      scheme,
      base::Passed(std::move(subscriber)),
      base::Passed(std::move(callback))));
}

void ServiceRegistry::SubscribeImpl(const std::string& scheme, common::mojom::ServiceSubscriberPtr subscriber, SubscribeCallback callback) {
  int id = ++next_watcher_id_;
  subscribers_.emplace(std::make_pair(id, std::make_pair(scheme, std::move(std::move(subscriber)))));
}

void ServiceRegistry::Unsubscribe(int id) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ServiceRegistry::UnsubscribeImpl, 
      base::Unretained(this),
      id));
}

void ServiceRegistry::UnsubscribeImpl(int id) {
  auto it = subscribers_.find(id);
  if (it != subscribers_.end()) {
    subscribers_.erase(it);
  }
}

// void ServiceRegistry::AddWatcher(const std::string& scheme, common::mojom::ServiceWatcherPtr watcher, AddWatcherCallback callback) {
//   HostThread::PostTask(
//     HostThread::UI, 
//     FROM_HERE, 
//     base::BindOnce(&ServiceRegistry::AddWatcherImpl, 
//       base::Unretained(this),
//       scheme,
//       base::Passed(std::move(watcher)),
//       base::Passed(std::move(callback))));
// }

// void ServiceRegistry::AddWatcherImpl(const std::string& scheme, common::mojom::ServiceWatcherPtr watcher, AddWatcherCallback callback) {
//   int id = ++next_watcher_id_;
//   watchers_.emplace(std::make_pair(id, std::make_pair(scheme, std::move(std::move(watcher)))));
// }

// void ServiceRegistry::RemoveWatcher(int watcher)  {
//   HostThread::PostTask(
//     HostThread::UI, 
//     FROM_HERE, 
//     base::BindOnce(&ServiceRegistry::RemoveWatcherImpl, 
//       base::Unretained(this),
//       watcher)); 
// }

// void ServiceRegistry::RemoveWatcherImpl(int watcher)  {
//   auto it = watchers_.find(watcher);
//   if (it != watchers_.end()) {
//     watchers_.erase(it);
//   }
// }


}