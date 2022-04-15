// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_registry.h"

#include "core/host/workspace/workspace.h"
#include "core/host/workspace/workspace_storage.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/rpc/server/rpc_manager.h"
#include "core/host/route/route_scheme.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/volume/volume_model.h"
#include "core/host/volume/volume.h"
#include "core/host/share/share.h"
#include "core/host/share/share_manager.h"
#include "core/host/application/domain_manager.h"
#include "core/host/application/domain.h"
#include "core/host/route/route_dispatcher_client.h"
#include "storage/storage.h"
#include "storage/proto/storage.pb.h"
#include "url/url_util.h"

namespace host {

namespace {

common::mojom::RouteEntryRPCMethodType FromRpcMethodType(net::RpcMethodType type) {
  switch (type) {
    case net::RpcMethodType::kNORMAL:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL;
    case net::RpcMethodType::kCLIENT_STREAM:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_CLIENT_STREAM;
    case net::RpcMethodType::kSERVER_STREAM:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM;
    case net::RpcMethodType::kBIDI_STREAM:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM;
  }
  return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL;
}

net::RpcMethodType GetMethodTypeFromProtobuf(const google::protobuf::MethodDescriptor* method) {
  if (method->client_streaming() && method->server_streaming()) {
    return net::RpcMethodType::kBIDI_STREAM;
  }
  if (method->client_streaming()) {
    return net::RpcMethodType::kCLIENT_STREAM;
  }
  if (method->server_streaming()) {
    return net::RpcMethodType::kSERVER_STREAM; 
  }
  return net::RpcMethodType::kNORMAL;
}

}

RouteRegistry::RouteRegistry(scoped_refptr<Workspace> workspace): 
  workspace_(workspace),
  shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED) {
  workspace_->AddObserver(this);
}

RouteRegistry::~RouteRegistry() {
  workspace_->RemoveObserver(this);
}

void RouteRegistry::Init() {
  OnLoad(net::OK, 0);
}

void RouteRegistry::Shutdown() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &RouteRegistry::ShutdownImpl, 
      base::Unretained(this)));
  shutdown_event_.Wait();
}

scoped_refptr<Workspace> RouteRegistry::workspace() const {
  return workspace_;
}

void RouteRegistry::ShutdownImpl() {
  for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
    it->second.second.reset();
  }
  route_registry_binding_.CloseAllBindings();
  shutdown_event_.Signal();
}

void RouteRegistry::AddBinding(common::mojom::RouteRegistryAssociatedRequest request) {
  route_registry_binding_.AddBinding(this, std::move(request));
}

void RouteRegistry::AddRoute(common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras, AddRouteCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::AddRouteImpl, 
      base::Unretained(this),
      base::Passed(std::move(entry)),
      base::Passed(std::move(extras)),
      base::Passed(std::move(callback))));
}

void RouteRegistry::AddRouteImpl(common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras, AddRouteCallback callback) {
  if (entry->path.empty()) {
    DLOG(ERROR) << "RouteRegistry::AddRoute: path of entry '" << entry->path << "' is empty. cancelling";
    if (!callback.is_null()) {
      HostThread::PostTask(
        HostThread::IO, 
        FROM_HERE,
        base::BindOnce(
          std::move(callback), 
          common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_PATH_EMPTY));
    }
    return;
  }
  std::string scheme_name = entry->url.scheme();
  RouteScheme* scheme = model_.GetScheme(scheme_name);
  if (!scheme) {
    storage::Storage* storage = GetStorageForSchemeName(scheme_name);
    if (!storage) {
      DLOG(ERROR) << "RouteRegistry::AddEntry: no storage named '" << scheme_name << "'. cancelling";
      if (!callback.is_null()) {
        HostThread::PostTask(
          HostThread::IO, 
          FROM_HERE,
          base::BindOnce(
            std::move(callback), 
            common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_FAILED));
      }
      return;
    }
    scheme = CreateScheme(storage, scheme_name);
  }
  RouteEntry* entry_ptr = nullptr;
  if (model_.HaveEntry(entry->path)) {
    entry_ptr = model_.GetEntry(entry->path);
  } else {
    entry_ptr = AddRouteInternal(scheme, std::move(entry), std::move(extras));
  }
  if (!callback.is_null()) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        entry_ptr ? 
          common::mojom::RouteStatusCode::kROUTE_STATUS_OK : 
          common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_FAILED));
  }
}

void RouteRegistry::AddOwnedEntry(RouteModel::OwnedEntry entry) {
  for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
    const common::mojom::RouteSubscriberPtr& watcher = it->second.second;
    watcher->OnRouteAdded(entry->entry_.Clone());
  }
  for (auto* observer : observers_) {
    observer->OnRouteAdded(entry.get());
  }
  model_.AddEntry(std::move(entry));
}

RouteEntry* RouteRegistry::AddRouteInternal(RouteScheme* scheme, common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras, bool from_service_created) {
  RouteEntry* entry_ptr = new RouteEntry(std::move(entry), std::move(extras));
  scheme->AddEntry(entry_ptr);
  model_.AddEntry(RouteModel::OwnedEntry(entry_ptr));

  if (!from_service_created) {
    /*
     * Sometimes a Entry is added after a service is started. 
     * in this case we fill the entry with info about the service method
     * it links to
     */
    RpcManager* rpc_manager = workspace_->rpc_manager();
    const std::unordered_map<base::UUID, HostRpcService *>& services = rpc_manager->services();
    for (auto it = services.begin(); it != services.end(); ++it) {
      HostRpcService* host_service = it->second;
      if (base::EqualsCaseInsensitiveASCII(host_service->container(), entry_ptr->url().scheme()) && 
          entry_ptr->type() == common::mojom::RouteEntryType::kROUTE_ENTRY_TYPE_ENTRY) {
          entry_ptr->set_service(host_service);
          const google::protobuf::ServiceDescriptor* main_descriptor = host_service->service_descriptor(); 
          const google::protobuf::ServiceDescriptor* plugin_descriptor = host_service->plugin_service_descriptor();
          BindEntryToRPCServiceMethods(host_service, main_descriptor, entry_ptr);
          if (plugin_descriptor) {
            BindEntryToRPCServiceMethods(host_service, plugin_descriptor, entry_ptr);
          }
      }
    }
  }

  for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
    const common::mojom::RouteSubscriberPtr& watcher = it->second.second;
    watcher->OnRouteAdded(entry.Clone());
  }

  for (auto* observer : observers_) {
    observer->OnRouteAdded(entry_ptr);
  }

  return entry_ptr;
}

void RouteRegistry::RemoveRoute(const std::string& path, RemoveRouteCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::RemoveRouteImpl, 
      base::Unretained(this),
      path,
      base::Passed(std::move(callback))));
}

void RouteRegistry::RemoveRouteImpl(const std::string& path, RemoveRouteCallback callback) {
  common::mojom::RouteEntryPtr entry_ptr;
  auto removed_entry = model_.RemoveEntry(path, &entry_ptr);
  if (removed_entry) {
    RouteScheme* parent = removed_entry->parent();
    DCHECK(parent);
    parent->RemoveEntry(removed_entry.get());
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
      const common::mojom::RouteSubscriberPtr& watcher = it->second.second;
      watcher->OnRouteRemoved(entry_ptr.Clone());
    }
    for (auto* observer : observers_) {
      observer->OnRouteRemoved(removed_entry.get());
    }
  }
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      removed_entry ? 
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK : 
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND));
}

void RouteRegistry::RemoveRouteByUrl(const GURL& url, RemoveRouteByUrlCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::RemoveRouteByUrlImpl, 
      base::Unretained(this),
      url,
      base::Passed(std::move(callback))));
}

void RouteRegistry::RemoveRouteByUrlImpl(const GURL& url, RemoveRouteByUrlCallback callback) {
  common::mojom::RouteEntryPtr entry_ptr;
  auto removed_entry = model_.RemoveEntry(url, &entry_ptr);
  if (removed_entry) {
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
      const common::mojom::RouteSubscriberPtr& watcher = it->second.second;
      watcher->OnRouteRemoved(entry_ptr.Clone());
    }
    for (auto* observer : observers_) {
      observer->OnRouteRemoved(removed_entry.get());
    }
  }
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      removed_entry ? 
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK : 
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND));
}

void RouteRegistry::RemoveRouteByUUID(const std::string& uuid, RemoveRouteByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::RemoveRouteByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void RouteRegistry::RemoveRouteByUUIDImpl(const std::string& uuid, RemoveRouteByUUIDCallback callback) {
  common::mojom::RouteEntryPtr entry_ptr;
  bool ok;
  base::UUID real_uuid = base::UUID::from_string(uuid, &ok);
  if (!ok) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND));
    return;
  }
  auto removed_entry = model_.RemoveEntry(real_uuid, &entry_ptr);
  if (removed_entry) {
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
      const common::mojom::RouteSubscriberPtr& watcher = it->second.second;
      watcher->OnRouteRemoved(entry_ptr.Clone());
    }
    for (auto* observer : observers_) {
      observer->OnRouteRemoved(removed_entry.get());
    }
  }
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      removed_entry ? 
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK : 
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND));
}
  
void RouteRegistry::LookupRoute(const std::string& scheme, const std::string& path, LookupRouteCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::LookupRouteImpl, 
      base::Unretained(this),
      scheme,
      path,
      base::Passed(std::move(callback))));
}

void RouteRegistry::LookupRouteImpl(const std::string& scheme_name, const std::string& path, LookupRouteCallback callback) {
  RouteEntry* entry = model_.GetEntry(path);
  if (entry) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK, 
        entry->entry_.Clone()));
    return;
  }
  RouteScheme* scheme = model_.GetScheme(scheme_name);
  if (!scheme) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND, 
        nullptr));
    return;
  }
  Domain* domain = scheme->domain();
  RouteDispatcherClient* dispatcher_client = domain->GetRouteDispatcherClient();
  common::mojom::RouteDispatcher* dispatcher = dispatcher_client->route_dispatcher();
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &RouteRegistry::LookupRouteOnDomainImpl,
      base::Unretained(this),
      base::Unretained(dispatcher),
      path,
      std::move(callback)));
}

void RouteRegistry::LookupRouteOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, LookupRouteCallback callback) {
  dispatcher->LookupRouteByPath(path, std::move(callback));
}

void RouteRegistry::LookupRouteByPath(const std::string& path, LookupRouteByPathCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::LookupRouteByPathImpl, 
      base::Unretained(this),
      path,
      base::Passed(std::move(callback))));
}

void RouteRegistry::LookupRouteByPathImpl(const std::string& path, LookupRouteByPathCallback callback) {
  RouteEntry* entry = model_.GetEntry(path);
  if (entry) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK, 
        entry->entry_.Clone()));
    return;
  }
  size_t offset = path.find_first_of(":");
  std::string scheme_name = path.substr(0, offset);
  DLOG(INFO) << "RouteRegistry::LookupRouteByPathImpl: looking up for scheme '" << scheme_name << "'";
  RouteScheme* scheme = model_.GetScheme(scheme_name);
  if (!scheme) {
    DLOG(INFO) << "RouteRegistry::LookupRouteByPathImpl: scheme '" << scheme_name << "' not found";
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND, 
        nullptr));
    return;
  }
  Domain* domain = scheme->domain();
  RouteDispatcherClient* dispatcher_client = domain->GetRouteDispatcherClient();
  common::mojom::RouteDispatcher* dispatcher = dispatcher_client->route_dispatcher();
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &RouteRegistry::LookupRouteByPathOnDomainImpl,
      base::Unretained(this),
      base::Unretained(dispatcher),
      path,
      std::move(callback)));
}

void RouteRegistry::LookupRouteByPathOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, LookupRouteByPathCallback callback) {
  dispatcher->LookupRouteByPath(path, std::move(callback)); 
}

void RouteRegistry::LookupRouteByUUID(const std::string& uuid, LookupRouteByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::LookupRouteByUUID, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void RouteRegistry::LookupRouteByUUIDImpl(const std::string& uuid, LookupRouteByUUIDCallback callback) {
  bool ok;
  base::UUID real_uuid = base::UUID::from_string(uuid, &ok);
  if (!ok) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND, 
        nullptr));
    return;
  }
  RouteEntry* entry = model_.GetEntry(real_uuid);
  if (entry) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK, 
        entry->entry_.Clone()));
    return;
  }
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND, 
      nullptr));
}

void RouteRegistry::LookupRouteByUrl(const GURL& url, LookupRouteByUrlCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::LookupRouteByUrlImpl, 
      base::Unretained(this),
      url,
      base::Passed(std::move(callback))));
}

void RouteRegistry::LookupRouteByUrlImpl(const GURL& url, LookupRouteByUrlCallback callback) {
  RouteEntry* entry = model_.GetEntry(url);
  if (entry) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_OK, 
        entry->entry_.Clone()));
    return;
  }
  RouteScheme* scheme = model_.GetScheme(url.scheme());
  if (!scheme) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback),
        common::mojom::RouteStatusCode::kROUTE_STATUS_ERR_ENTRY_NOT_FOUND, 
        nullptr));
    return;
  }
  Domain* domain = scheme->domain();
  RouteDispatcherClient* dispatcher_client = domain->GetRouteDispatcherClient();
  common::mojom::RouteDispatcher* dispatcher = dispatcher_client->route_dispatcher();
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &RouteRegistry::LookupRouteByUrlOnDomainImpl,
      base::Unretained(this),
      base::Unretained(dispatcher),
      url,
      std::move(callback)));
}

void RouteRegistry::LookupRouteByUrlOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const GURL& url, LookupRouteByUrlCallback callback) {
  dispatcher->LookupRouteByUrl(url, std::move(callback));  
}

void RouteRegistry::HaveRoute(const std::string& path, HaveRouteCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::HaveRouteImpl, 
      base::Unretained(this),
      path,
      base::Passed(std::move(callback))));
}

void RouteRegistry::HaveRouteImpl(const std::string& path, HaveRouteCallback callback) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      model_.HaveEntry(path)));
}

void RouteRegistry::HaveRouteByUrl(const GURL& url, HaveRouteByUrlCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::HaveRouteByUrlImpl, 
      base::Unretained(this),
      url,
      base::Passed(std::move(callback))));
}

void RouteRegistry::HaveRouteByUrlImpl(const GURL& url, HaveRouteByUrlCallback callback) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      model_.HaveEntry(url)));
}

void RouteRegistry::HaveRouteByUUID(const std::string& uuid, HaveRouteByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::HaveRouteByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void RouteRegistry::HaveRouteByUUIDImpl(const std::string& uuid, HaveRouteByUUIDCallback callback) {
  bool ok;
  base::UUID real_uuid = base::UUID::from_string(uuid, &ok);
  if (!ok) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), false));
    return;
  }
  HostThread::PostTask(
    HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        model_.HaveEntry(real_uuid)));
}

void RouteRegistry::ListSchemes(ListSchemesCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::ListSchemesImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void RouteRegistry::ListSchemesImpl(ListSchemesCallback callback) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      base::Passed(model_.GetAllSchemes())));
}

void RouteRegistry::ListRoutes(ListRoutesCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::ListRoutesImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void RouteRegistry::ListRoutesImpl(ListRoutesCallback callback) {
  std::vector<common::mojom::RouteEntryPtr> result = model_.GetAllMojoEntries();
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      base::Passed(std::move(result))));
}

void RouteRegistry::ListRoutesForScheme(const std::string& scheme, ListRoutesForSchemeCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::ListRoutesForSchemeImpl, 
      base::Unretained(this),
      scheme,
      base::Passed(std::move(callback))));
}

void RouteRegistry::ListRoutesForSchemeImpl(const std::string& scheme, ListRoutesForSchemeCallback callback) {
  std::vector<common::mojom::RouteEntryPtr> result = model_.GetMojoEntriesForScheme(scheme);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      base::Passed(std::move(result))));
}

void RouteRegistry::GetRouteCount(GetRouteCountCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::GetRouteCountImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void RouteRegistry::GetRouteCountImpl(GetRouteCountCallback callback) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback),
      model_.entry_count()));
}

void RouteRegistry::GetRouteCountByScheme(const std::string& scheme, GetRouteCountBySchemeCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::GetRouteCountBySchemeImpl, 
      base::Unretained(this),
      scheme,
      base::Passed(std::move(callback))));
}

void RouteRegistry::GetRouteCountBySchemeImpl(const std::string& scheme_name, GetRouteCountBySchemeCallback callback) {
  RouteScheme* scheme = model_.GetScheme(scheme_name);
  if (!scheme) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        -1));
    return;
  }
  Domain* domain = scheme->domain();
  RouteDispatcherClient* dispatcher_client = domain->GetRouteDispatcherClient();
  common::mojom::RouteDispatcher* dispatcher = dispatcher_client->route_dispatcher();
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &RouteRegistry::GetRouteCountBySchemeOnDomainImpl,
      base::Unretained(this),
      base::Unretained(dispatcher),
      std::move(callback)));
}

void RouteRegistry::GetRouteCountBySchemeOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, GetRouteCountBySchemeCallback callback) {
  dispatcher->GetRouteCount(std::move(callback));  
}

void RouteRegistry::GetRouteHeader(const std::string& scheme, const std::string& path, GetRouteHeaderCallback callback) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&RouteRegistry::GetRouteHeaderImpl, 
      base::Unretained(this),
      scheme,
      path,
      base::Passed(std::move(callback))));
}

void RouteRegistry::GetRouteHeaderImpl(const std::string& scheme_name, const std::string& path, GetRouteHeaderCallback callback) {
  network::ResourceResponseHead none;
  RouteScheme* scheme = model_.GetScheme(scheme_name);
  if (!scheme) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        base::Passed(std::move(none))));
    return;
  }
  Domain* domain = scheme->domain();
  RouteDispatcherClient* dispatcher_client = domain->GetRouteDispatcherClient();
  common::mojom::RouteDispatcher* dispatcher = dispatcher_client->route_dispatcher();
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &RouteRegistry::GetRouteHeaderOnDomainImpl,
      base::Unretained(this),
      base::Unretained(dispatcher),
      path,
      std::move(callback)));
}

void RouteRegistry::GetRouteHeaderOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, GetRouteHeaderCallback callback) {
  dispatcher->GetRouteHeader(path, std::move(callback));
}

void RouteRegistry::Subscribe(const std::string& scheme, common::mojom::RouteSubscriberPtr subscriber, SubscribeCallback callback) {
  int id = ++next_subscriber_id_;
  subscribers_.emplace(std::make_pair(id, std::make_pair(scheme, std::move(std::move(subscriber)))));
}

void RouteRegistry::Unsubscribe(int subscriber_id) {
  auto it = subscribers_.find(subscriber_id);
  if (it != subscribers_.end()) {
    subscribers_.erase(it);
  }
}

std::vector<RouteEntry*> RouteRegistry::ListEntriesForScheme(const std::string& scheme) {
  return model_.GetEntriesForScheme(scheme);
}

void RouteRegistry::OnServiceCreated(HostRpcService* host_service) {
  //entry_ptr->set_service(service);
  std::string scheme_name = host_service->container();
  RouteScheme* scheme = model_.GetScheme(scheme_name);
  if (!scheme) {
    storage::Storage* storage = GetStorageForSchemeName(scheme_name);
    if (!storage) {
      DLOG(ERROR) << "RouteRegistry::OnServiceCreated: no storage named '" << scheme_name << "'. cancelling";
      return;
    }
    
    scheme = CreateScheme(storage, scheme_name);
  }

  scheme->set_service(host_service);

  // Add a entry for each service method
  //Schema* schema = host_service->schema();
  //const google::protobuf::ServiceDescriptor* descriptor = proto->GetServiceDescriptorNamed("MumbaManager");
  //DLOG(INFO) << "RouteRegistry::OnServiceCreated: getting ServiceDescriptor named: " << host_service->name();
  const google::protobuf::ServiceDescriptor* main_descriptor = host_service->service_descriptor();//schema->GetServiceDescriptorNamed(host_service->name());
  const google::protobuf::ServiceDescriptor* plugin_descriptor = host_service->plugin_service_descriptor();
  std::vector<RouteEntry*> entries = model_.GetEntriesForScheme(scheme_name);

  BindEntriesToRPCServiceMethods(host_service, main_descriptor, &entries);
  if (plugin_descriptor) {
    BindEntriesToRPCServiceMethods(host_service, plugin_descriptor, &entries);
  }
}

void RouteRegistry::LinkRouteEntriesWithRPCServiceMethod(
  HostRpcService* host_service, 
  const std::string& scheme_name,
  const net::RpcDescriptor& descr,
  const std::vector<RouteEntry*>& entries) {
  for (RouteEntry* entry : entries) {
    LinkRouteEntryWithRPCServiceMethod(host_service, scheme_name, descr, entry);
  }
}

void RouteRegistry::LinkRouteEntryWithRPCServiceMethod(
  HostRpcService* host_service, 
  const std::string& scheme_name,
  const net::RpcDescriptor& descr,
  RouteEntry* entry) {
  
  // DLOG(INFO) << "linking method with url entry. comparing '" << entry->name() << "' and '" << descr.name << "' url entry type = " << entry->type();  

  if (descr.name == "FetchUnary" && entry->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL) {
    //DLOG(INFO) << entry->name() << " => FetchUnary";
    entry->set_service(host_service);
    entry->set_fullname(descr.full_name);
    //entry->set_rpc_method_type(FromRpcMethodType(descr.method_type));
    entry->set_rpc_descriptor(descr);
  } else if (descr.name == "FetchClientStream" && entry->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_CLIENT_STREAM) {
    //DLOG(INFO) << entry->name() << " => FetchClientStrem";
    entry->set_service(host_service);
    entry->set_fullname(descr.full_name);
    entry->set_rpc_descriptor(descr);
  } else if (descr.name == "FetchServerStream" && entry->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM) {
    //DLOG(INFO) << entry->name() << " => FetchServerStream";
    entry->set_service(host_service);
    entry->set_fullname(descr.full_name);
    entry->set_rpc_descriptor(descr);
  } else if (descr.name == "FetchBidiStream" && entry->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM) {
    //DLOG(INFO) << entry->name() << " => FetchBidiStream";
    entry->set_service(host_service);
    entry->set_fullname(descr.full_name);
    entry->set_rpc_descriptor(descr);
  //  normal rpc methods are also deserving of routes and services binded to those routes
  } else if (base::EqualsCaseInsensitiveASCII(entry->name(), descr.name) && 
      entry->type() == common::mojom::RouteEntryType::kROUTE_ENTRY_TYPE_ENTRY) {
    //DLOG(INFO) << "equals => binding service '" << host_service->name() << "' with entry '" << entry->name() << "'";    
    entry->set_service(host_service);
    entry->set_fullname(descr.full_name);
    entry->set_rpc_method_type(FromRpcMethodType(descr.method_type));
    entry->set_rpc_descriptor(descr);
  }
}

void RouteRegistry::AddScheme(std::unique_ptr<RouteScheme> scheme) {
  model_.AddScheme(std::move(scheme));
}

void RouteRegistry::RemoveScheme(const std::string& scheme_name) {
  model_.RemoveScheme(scheme_name);
} 

RouteScheme* RouteRegistry::GetScheme(const std::string& scheme_name) {
  return model_.GetScheme(scheme_name);
}

bool RouteRegistry::HasScheme(const std::string& scheme_name) {
  return model_.HasScheme(scheme_name);
}

bool RouteRegistry::HaveRouteByName(const std::string& name) {
  return model_.HaveEntry(name);
}

bool RouteRegistry::HaveRouteById(const base::UUID& uuid) {
  return model_.HaveEntry(uuid);
}

RouteEntry* RouteRegistry::LookupRouteByName(const std::string& name) {
  return model_.GetEntry(name);
}

RouteEntry* RouteRegistry::LookupRouteById(const base::UUID& id) {
  return model_.GetEntry(id);
}

void RouteRegistry::AddObserver(RouteObserver* observer) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  //observers_.AddObserver(observer);
  observers_.push_back(observer);
}

void RouteRegistry::RemoveObserver(RouteObserver* observer) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (*it == observer) {
      observers_.erase(it);
      return;
    }
  }
}

storage::Storage* RouteRegistry::GetStorageForSchemeName(const std::string& scheme_name) const {
  if (scheme_name == "mumba") {
    return workspace_->workspace_storage()->workspace_disk();
  }  
  Volume* volume = workspace_->volume_manager()->volumes()->GetVolumeByName(scheme_name);
  return volume ? volume->volume_storage() : nullptr;
}

RouteScheme* RouteRegistry::CreateScheme(storage::Storage* storage, const std::string& scheme_name) {
  ShareManager* share_manager = workspace_->share_manager();
  DomainManager* domain_manager = workspace_->domain_manager();
  const storage_proto::StorageState* storage_state = storage->state();
  scoped_refptr<storage::Torrent> torrent = storage->root_tree();

  Domain* domain = domain_manager->GetDomain(scheme_name);
  //DCHECK(domain);
  
  std::unique_ptr<RouteScheme> owned_scheme = std::make_unique<RouteScheme>(this);
  owned_scheme->set_name(scheme_name);
  owned_scheme->set_type(common::mojom::RouteEntryType::kROUTE_ENTRY_TYPE_SCHEME);
  owned_scheme->set_transport_type(common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_IPC);
  std::unique_ptr<Share> owned_share = std::make_unique<Share>(share_manager, scheme_name, torrent, std::vector<std::string>(), false);
  Share* share = owned_share.get();
  RouteScheme* scheme = owned_scheme.get();
  share_manager->InsertShare(std::move(owned_share));
  DCHECK(share);
  scheme->set_share(share);
  scheme->set_dht_public_key(storage_state->pubkey());
  scheme->set_domain(domain);

  model_.AddScheme(std::move(owned_scheme));

  url::AddCORSEnabledScheme(scheme_name.c_str());

  //DLOG(INFO) << "RouteRegistry: DHT address for scheme '" << scheme_name << "': " << 
  //  base::HexEncode(scheme->dht_public_key().data(), scheme->dht_public_key().size());
  return scheme;
}

void RouteRegistry::OnLoad(int r, int count) {
  NotifyRouteEntriesLoad(r, count);
}

void RouteRegistry::NotifyRouteEntriesLoad(int r, int count) {
  for (auto* observer : observers_) {
    observer->OnRouteEntriesLoad(r, count);
  }
}

void RouteRegistry::BindEntryToRPCServiceMethods(HostRpcService* host_service, const google::protobuf::ServiceDescriptor* descriptor, RouteEntry* entry) {
  std::string scheme_name = host_service->container();
  for (int i = 0; i < descriptor->method_count(); ++i) {
    const google::protobuf::MethodDescriptor* method = descriptor->method(i);
    net::RpcDescriptor descr;
    descr.full_name = method->full_name();
    descr.name = method->name();
    descr.uuid = base::UUID::generate();
    descr.transport_type = host_service->transport_type();
    descr.method_type = GetMethodTypeFromProtobuf(method);
    // NOW lets make ROUTE entries linked
    LinkRouteEntryWithRPCServiceMethod(host_service, scheme_name, descr, entry);
  }
}

void RouteRegistry::BindEntriesToRPCServiceMethods(HostRpcService* host_service, const google::protobuf::ServiceDescriptor* descriptor, std::vector<RouteEntry*>* entries) {
  std::string scheme_name = host_service->container();
  for (int i = 0; i < descriptor->method_count(); ++i) {
    const google::protobuf::MethodDescriptor* method = descriptor->method(i);
    net::RpcDescriptor descr;
    descr.full_name = method->full_name();
    descr.name = method->name();
    descr.uuid = base::UUID::generate();
    descr.transport_type = host_service->transport_type();
    descr.method_type = GetMethodTypeFromProtobuf(method);
    // NOW lets make ROUTE entries linked
    LinkRouteEntriesWithRPCServiceMethod(host_service, scheme_name, descr, *entries);
  }
}

const google::protobuf::Descriptor* RouteRegistry::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Route");
}

std::string RouteRegistry::resource_classname() const {
  return RouteEntry::kClassName;
}

}