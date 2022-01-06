// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_RESOLVER_H_
#define MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_RESOLVER_H_

#include <string>

#include "base/macros.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/weak_ptr.h"
#include "core/shared/common/mojom/route.mojom.h"

namespace host {
class RouteRegistry;
class RouteEntry;
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
class RouteResolver {
public:
  RouteResolver(RouteRegistry* route_registry);
  ~RouteResolver();

  RouteRegistry* registry() const {
    return route_registry_;
  }

  // Given a url: "application:bloggy"
  // a) check if theres a cached entry already. if yes, just return that
  // b) iterate over graphs to see if theres a match by type:value
  // c) if so, create a new RouteEntry and adds it on registry
  // d) return the new entry
  void ResolveAsync(const std::string& scheme, const std::string& path, base::Callback<void(int, RouteEntry*)> on_resolve);

private:

  void ResolveJob(const std::string& scheme, const std::string& path, base::Callback<void(int, RouteEntry*)> on_resolve);
  void LookupRouteOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, base::Callback<void(int, RouteEntry*)> on_resolve);
  void OnLookupRouteCompletion(base::Callback<void(int, RouteEntry*)> on_resolve, common::mojom::RouteStatusCode code, common::mojom::RouteEntryPtr entry);
  
  RouteEntry* Resolve(const std::string& scheme, const std::string& path);
  
  RouteRegistry* route_registry_;
  scoped_refptr<base::SingleThreadTaskRunner> reply_to_;
  
  DISALLOW_COPY_AND_ASSIGN(RouteResolver);
};

}

#endif