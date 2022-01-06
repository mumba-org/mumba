// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/appcache/chrome_appcache_service.h"

#include "base/files/file_path.h"
#include "core/host/appcache/appcache_storage_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/host/application/resource_context.h"
#include "net/base/net_errors.h"
#include "net/url_request/url_request_context_getter.h"
#include "storage/host/quota/quota_manager.h"

namespace host {

ChromeAppCacheService::ChromeAppCacheService(
    storage::QuotaManagerProxy* quota_manager_proxy)
    : AppCacheServiceImpl(quota_manager_proxy), resource_context_(nullptr) {}

void ChromeAppCacheService::InitializeOnIOThread(
    const base::FilePath& cache_path,
    ResourceContext* resource_context,
    net::URLRequestContextGetter* request_context_getter,
    scoped_refptr<storage::SpecialStoragePolicy> special_storage_policy) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  cache_path_ = cache_path;
  resource_context_ = resource_context;

  // The |request_context_getter| can be NULL in some unit tests.
  //
  // TODO(ajwong): TestProfile is difficult to work with. The
  // SafeBrowsing tests require that GetRequestContext return NULL
  // so we can't depend on having a non-NULL value here. See crbug/149783.
  if (request_context_getter)
    set_request_context(request_context_getter->GetURLRequestContext());

  // Init our base class.
  Initialize(cache_path_);
  set_appcache_policy(this);
  set_special_storage_policy(special_storage_policy.get());
}

void ChromeAppCacheService::Bind(
    std::unique_ptr<common::mojom::AppCacheBackend> backend,
    common::mojom::AppCacheBackendRequest request) {
  bindings_.AddBinding(std::move(backend), std::move(request));
}

void ChromeAppCacheService::Shutdown() {
  bindings_.CloseAllBindings();
}

bool ChromeAppCacheService::CanLoadAppCache(const GURL& manifest_url,
                                            const GURL& first_party) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // We don't prompt for read access.
  // return GetClient()->browser()->AllowAppCache(
  //     manifest_url, first_party, resource_context_);
  return true;
}

bool ChromeAppCacheService::CanCreateAppCache(
    const GURL& manifest_url, const GURL& first_party) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  //return GetClient()->browser()->AllowAppCache(
      //manifest_url, first_party, resource_context_);
  return true;
}

ChromeAppCacheService::~ChromeAppCacheService() {}

void ChromeAppCacheService::DeleteOnCorrectThread() const {
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    delete this;
    return;
  }
  if (HostThread::IsThreadInitialized(HostThread::IO)) {
    HostThread::DeleteSoon(HostThread::IO, FROM_HERE, this);
    return;
  }
  // Better to leak than crash on shutdown.
}

}  // namespace host
