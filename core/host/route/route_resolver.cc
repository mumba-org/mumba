// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_resolver.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/application/domain.h"
#include "core/host/route/route_resolver.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
#include "core/host/route/route_scheme.h"
#include "core/host/route/route_model.h"
#include "core/host/route/route_dispatcher_client.h"

namespace host {

namespace {

bool IsSystemScheme(const std::string& scheme) {
  static std::vector<std::string> system_schemes = {
    "application",
    "device",
    "channel",
    "graph",
    "identity",
    "route",
    "repo",
    "service",
    "schema",
    "volume"
  };
  for (const auto& item : system_schemes) {
    if (scheme == item) {
      return true;
    }
  }
  return false;
}

}

RouteResolver::RouteResolver(RouteRegistry* route_registry):
 route_registry_(route_registry) {
  
}

RouteResolver::~RouteResolver() {

}

void RouteResolver::ResolveAsync(const std::string& scheme, const std::string& path, base::Callback<void(int, RouteEntry*)> on_resolve) {
  reply_to_ = base::ThreadTaskRunnerHandle::Get();
  base::PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RouteResolver::ResolveJob, 
      base::Unretained(this), 
      scheme, 
      path, 
      base::Passed(std::move(on_resolve))));
}

void RouteResolver::ResolveJob(const std::string& scheme_name, const std::string& path, base::Callback<void(int, RouteEntry*)> on_resolve) {
  RouteEntry* entry = Resolve(scheme_name, path);
  // the entry is alredy cached, so just return that
  if (entry) {
    DLOG(INFO) << "found a cached entry for " << scheme_name << " " << path << ". returning it";
    reply_to_->PostTask(FROM_HERE,
                        base::BindOnce(
                          std::move(on_resolve), 
                          net::OK, 
                          entry));
    return;
  }
  // we ping back the domain process to check for the route
  RouteScheme* scheme = route_registry_->model()->GetScheme(scheme_name);
  if (!scheme) {
    reply_to_->PostTask(
      FROM_HERE,
      base::BindOnce(
        std::move(on_resolve),
        net::ERR_FAILED, 
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
      &RouteResolver::LookupRouteOnDomainImpl,
      base::Unretained(this),
      base::Unretained(dispatcher),
      path,
      base::Passed(std::move(on_resolve))));
}

void RouteResolver::LookupRouteOnDomainImpl(common::mojom::RouteDispatcher* dispatcher, const std::string& path, base::Callback<void(int, RouteEntry*)> on_resolve) {
  dispatcher->LookupRouteByPath(path, 
                                base::BindOnce(
                                  &RouteResolver::OnLookupRouteCompletion,
                                  base::Unretained(this),
                                  base::Passed(std::move(on_resolve))));
}

void RouteResolver::OnLookupRouteCompletion(base::Callback<void(int, RouteEntry*)> on_resolve, common::mojom::RouteStatusCode code, common::mojom::RouteEntryPtr entry) {
  if (code != common::mojom::RouteStatusCode::kROUTE_STATUS_OK) {
    reply_to_->PostTask(
      FROM_HERE,
      base::BindOnce(
        std::move(on_resolve),
        net::ERR_FAILED, 
        nullptr));
    return;
  }
  // add it to the registry
  std::string scheme_name = entry->url.scheme();
  RouteScheme* scheme = route_registry_->model()->GetScheme(scheme_name);
  DCHECK(scheme);
  common::mojom::RouteEntryExtrasPtr extras;
  RouteEntry* entry_ptr = route_registry_->AddRouteInternal(scheme, std::move(entry), std::move(extras));
  reply_to_->PostTask(
      FROM_HERE,
      base::BindOnce(
        std::move(on_resolve),
        net::OK, 
        base::Unretained(entry_ptr)));
}

RouteEntry* RouteResolver::Resolve(const std::string& scheme, const std::string& path) {
  std::string tree_name = IsSystemScheme(scheme) ? "system" : scheme; 
  RouteEntry* entry = route_registry_->model()->GetEntry(scheme, path);
  return entry;
}

}