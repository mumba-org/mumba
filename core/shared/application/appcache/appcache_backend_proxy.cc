// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/appcache/appcache_backend_proxy.h"
#include "core/shared/common/appcache.mojom.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/application/application_thread.h"
#include "services/service_manager/public/cpp/connector.h"

namespace application {

AppCacheBackendProxy::AppCacheBackendProxy() = default;
AppCacheBackendProxy::~AppCacheBackendProxy() = default;

common::mojom::AppCacheBackend* AppCacheBackendProxy::GetAppCacheBackendPtr() {
  if (!app_cache_backend_ptr_) {
    ApplicationThread::current()->GetConnector()->BindInterface(
        common::mojom::kHostServiceName, mojo::MakeRequest(&app_cache_backend_ptr_));
  }
  return app_cache_backend_ptr_.get();
}

void AppCacheBackendProxy::RegisterHost(int host_id) {
  GetAppCacheBackendPtr()->RegisterHost(host_id);
}

void AppCacheBackendProxy::UnregisterHost(int host_id) {
  GetAppCacheBackendPtr()->UnregisterHost(host_id);
}

void AppCacheBackendProxy::SetSpawningHostId(int host_id,
                                             int spawning_host_id) {
  GetAppCacheBackendPtr()->SetSpawningHostId(host_id, spawning_host_id);
}

void AppCacheBackendProxy::SelectCache(
    int host_id,
    const GURL& document_url,
    const int64_t cache_document_was_loaded_from,
    const GURL& manifest_url) {
  GetAppCacheBackendPtr()->SelectCache(
      host_id, document_url, cache_document_was_loaded_from, manifest_url);
}

void AppCacheBackendProxy::SelectCacheForSharedWorker(int host_id,
                                                      int64_t appcache_id) {
  GetAppCacheBackendPtr()->SelectCacheForSharedWorker(host_id, appcache_id);
}

void AppCacheBackendProxy::MarkAsForeignEntry(
    int host_id,
    const GURL& document_url,
    int64_t cache_document_was_loaded_from) {
  GetAppCacheBackendPtr()->MarkAsForeignEntry(host_id, document_url,
                                              cache_document_was_loaded_from);
}

common::AppCacheStatus AppCacheBackendProxy::GetStatus(int host_id) {
  common::AppCacheStatus status = common::AppCacheStatus::APPCACHE_STATUS_UNCACHED;
  GetAppCacheBackendPtr()->GetStatus(host_id, &status);
  return status;
}

bool AppCacheBackendProxy::StartUpdate(int host_id) {
  bool result = false;
  GetAppCacheBackendPtr()->StartUpdate(host_id, &result);
  return result;
}

bool AppCacheBackendProxy::SwapCache(int host_id) {
  bool result = false;
  GetAppCacheBackendPtr()->SwapCache(host_id, &result);
  return result;
}

void AppCacheBackendProxy::GetResourceList(
    int host_id, std::vector<common::AppCacheResourceInfo>* resource_infos) {
  std::vector<common::mojom::AppCacheResourceInfoPtr> boxed_infos;
  GetAppCacheBackendPtr()->GetResourceList(host_id, &boxed_infos);
  for (auto& b : boxed_infos) {
    resource_infos->emplace_back(std::move(*b));
  }
}

}  // namespace content
