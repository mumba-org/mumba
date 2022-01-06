// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REGISTRY_H_
#define MUMBA_CORE_HOST_ROUTE_REGISTRY_H_

#include <string>
#include <unordered_map>
#include <map>
#include <vector>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/memory/ref_counted_memory.h"
#include "base/observer_list.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/workspace_observer.h"
#include "core/host/route/route_entry.h"
#include "core/host/route/route_model.h"
#include "core/host/route/route_observer.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"

namespace google {
namespace protobuf {
class ServiceDescriptor;
}
}

namespace storage {
class Storage;  
}

namespace host {
class Workspace;
class RouteScheme;

/*
 * FIXME: route entries from applications are not added directly here anymore.
 *        they are added as a 'Page' object which can then be resolved to a 'Route'
 *        object by the RouteResolver.
 *        RouteResolver is a consumer of RouteRegistry which add a new Route
 *        once it resolves the input to something (like one or more 'Page's) but
 *        the Route is not cached.
 *        To do this in a sane way we need that the input can be indexable
 *        So we can use the input as a key to know wether we already have it
 *        in the registry
 */
class CONTENT_EXPORT RouteRegistry final : public common::mojom::RouteRegistry,
                                           public WorkspaceObserver {
public:
  RouteRegistry(scoped_refptr<Workspace> workspace);
  ~RouteRegistry() override;

  void AddBinding(common::mojom::RouteRegistryAssociatedRequest request);

  RouteModel* model() {
    return &model_;
  }

  scoped_refptr<Workspace> workspace() const;

  void AddRoute(common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras, AddRouteCallback callback) final;
  void RemoveRoute(const std::string& path, RemoveRouteCallback callback) final;
  void RemoveRouteByUrl(const GURL& url, RemoveRouteByUrlCallback callback) final;
  void RemoveRouteByUUID(const std::string& uuid, RemoveRouteByUUIDCallback callback) final;
  void LookupRoute(const std::string& scheme, const std::string& path, LookupRouteCallback callback) final;
  void LookupRouteByPath(const std::string& path, LookupRouteByPathCallback callback) final;
  void LookupRouteByUrl(const GURL& url, LookupRouteByUrlCallback callback) final;
  void LookupRouteByUUID(const std::string& uuid, LookupRouteByUUIDCallback callback) final;
  void HaveRoute(const std::string& path, HaveRouteCallback callback) final;
  void HaveRouteByUrl(const GURL& url, HaveRouteByUrlCallback callback) final;
  void HaveRouteByUUID(const std::string& uuid, HaveRouteByUUIDCallback callback) final;
  void ListSchemes(ListSchemesCallback callback) final;
  void ListRoutes(ListRoutesCallback callback) final;
  void ListRoutesForScheme(const std::string& scheme, ListRoutesForSchemeCallback callback) final;
  void GetRouteCount(GetRouteCountCallback callback) final;
  void GetRouteCountByScheme(const std::string& scheme, GetRouteCountBySchemeCallback callback) final;
  void GetRouteHeader(const std::string& scheme, const std::string& path, GetRouteHeaderCallback callback) final;

  
  void Subscribe(const std::string& scheme, common::mojom::RouteSubscriberPtr subscriber, SubscribeCallback callback) final;
  void Unsubscribe(int subscriber_id) final;

  void AddOwnedEntry(RouteModel::OwnedEntry entry);
  
  std::vector<RouteEntry*> ListEntriesForScheme(const std::string& scheme);
  
  // WorkspaceObserver
  void OnServiceCreated(HostRpcService* service) override;

  void AddScheme(std::unique_ptr<RouteScheme> scheme);
  void RemoveScheme(const std::string& scheme_name);
  RouteScheme* GetScheme(const std::string& scheme_name);
  bool HasScheme(const std::string& scheme_name);

  void AddObserver(RouteObserver* observer);
  void RemoveObserver(RouteObserver* observer);

  void Init();
  void Shutdown();

private:

  friend class RouteResolver;

  void AddRouteImpl(common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras, AddRouteCallback callback);
  void RemoveRouteImpl(const std::string& path, RemoveRouteCallback callback);
  void RemoveRouteByUrlImpl(const GURL& url, RemoveRouteByUrlCallback callback);
  void RemoveRouteByUUIDImpl(const std::string& uuid, RemoveRouteByUUIDCallback callback);
  void LookupRouteImpl(const std::string& scheme, const std::string& path, LookupRouteCallback callback);
  void LookupRouteByPathImpl(const std::string& path, LookupRouteByPathCallback callback);
  void LookupRouteByUrlImpl(const GURL& url, LookupRouteByUrlCallback callback);
  void LookupRouteByUUIDImpl(const std::string& uuid, LookupRouteByUUIDCallback callback);
  void HaveRouteImpl(const std::string& path, HaveRouteCallback callback);
  void HaveRouteByUrlImpl(const GURL& url, HaveRouteByUrlCallback callback);
  void HaveRouteByUUIDImpl(const std::string& uuid, HaveRouteByUUIDCallback callback);
  void ListSchemesImpl(ListSchemesCallback callback);
  void ListRoutesImpl(ListRoutesCallback callback);
  void ListRoutesForSchemeImpl(const std::string& scheme, ListRoutesForSchemeCallback callback);
  void GetRouteCountImpl(GetRouteCountCallback callback);
  void GetRouteCountBySchemeImpl(const std::string& scheme, GetRouteCountBySchemeCallback callback);
  void GetRouteHeaderImpl(const std::string& scheme, const std::string& path, GetRouteHeaderCallback callback);

  void GetRouteCountBySchemeOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, GetRouteCountBySchemeCallback callback);
  void GetRouteHeaderOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, GetRouteHeaderCallback callback);


  void LookupRouteOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, LookupRouteCallback callback);
  void LookupRouteByPathOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, LookupRouteByPathCallback callback);
  void LookupRouteByUrlOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const GURL& url, LookupRouteByUrlCallback callback);
  //void LookupRouteByUUIDOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& uuid, LookupRouteByUUIDCallback callback);

  // void AddHandlerImpl(common::mojom::RouteHandlerPtr handler, AddHandlerCallback callback);
  // void RemoveHandlerImpl(const std::string& handler_name, RemoveHandlerCallback callback);
  // void LookupHandlerImpl(const std::string& handler_name, LookupHandlerCallback callback);
  // void HaveHandlerImpl(const std::string& handler_name, HaveHandlerCallback callback);
  // void ListHandlersImpl(ListHandlersCallback callback);

  RouteEntry* AddRouteInternal(RouteScheme* scheme, common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras, bool from_service_created = false);
  storage::Storage* GetStorageForSchemeName(const std::string& scheme_name) const;
  RouteScheme* CreateScheme(storage::Storage* storage, const std::string& scheme_name);
  void BindEntryToRPCServiceMethods(
    HostRpcService* host_service, 
    const google::protobuf::ServiceDescriptor* descriptor, 
    RouteEntry* entry);
  void BindEntriesToRPCServiceMethods(
    HostRpcService* host_service, 
    const google::protobuf::ServiceDescriptor* descriptor, 
    std::vector<RouteEntry*>* entries);
  void LinkRouteEntriesWithRPCServiceMethod(
    HostRpcService* host_service, 
    const std::string& scheme_name,
    const net::RpcDescriptor& descr,
    const std::vector<RouteEntry*>& entries);
  void LinkRouteEntryWithRPCServiceMethod(
    HostRpcService* host_service, 
    const std::string& scheme_name,
    const net::RpcDescriptor& descr,
    RouteEntry* entry);

  void OnLoad(int r, int count);
  void NotifyRouteEntriesLoad(int r, int count);
  void ShutdownImpl();

  scoped_refptr<Workspace> workspace_;

  std::map<int, std::pair<std::string, common::mojom::RouteSubscriberPtr>> subscribers_;
  
  RouteModel model_;
  
  mojo::AssociatedBindingSet<common::mojom::RouteRegistry> route_registry_binding_;

  int next_subscriber_id_ = 0;

  //base::ObserverList<Observer> observers_;
  std::vector<RouteObserver *> observers_;

  base::WaitableEvent shutdown_event_;

  DISALLOW_COPY_AND_ASSIGN(RouteRegistry);
};

}

#endif