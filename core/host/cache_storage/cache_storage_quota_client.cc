// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/cache_storage/cache_storage_quota_client.h"

#include "core/host/cache_storage/cache_storage_manager.h"
#include "core/host/host_thread.h"
#include "third_party/blink/public/mojom/quota/quota_types.mojom.h"
#include "url/origin.h"

namespace host {

CacheStorageQuotaClient::CacheStorageQuotaClient(
    base::WeakPtr<CacheStorageManager> cache_manager)
    : cache_manager_(cache_manager) {
}

CacheStorageQuotaClient::~CacheStorageQuotaClient() {
}

storage::QuotaClient::ID CacheStorageQuotaClient::id() const {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  return kServiceWorkerCache;
}

void CacheStorageQuotaClient::OnQuotaManagerDestroyed() {
  delete this;
}

void CacheStorageQuotaClient::GetOriginUsage(const url::Origin& origin,
                                             blink::mojom::StorageType type,
                                             GetUsageCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!cache_manager_ || !DoesSupport(type)) {
    std::move(callback).Run(0);
    return;
  }

  cache_manager_->GetOriginUsage(origin, std::move(callback));
}

void CacheStorageQuotaClient::GetOriginsForType(blink::mojom::StorageType type,
                                                GetOriginsCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!cache_manager_ || !DoesSupport(type)) {
    std::move(callback).Run(std::set<url::Origin>());
    return;
  }

  cache_manager_->GetOrigins(std::move(callback));
}

void CacheStorageQuotaClient::GetOriginsForHost(blink::mojom::StorageType type,
                                                const std::string& host,
                                                GetOriginsCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!cache_manager_ || !DoesSupport(type)) {
    std::move(callback).Run(std::set<url::Origin>());
    return;
  }

  cache_manager_->GetOriginsForHost(host, std::move(callback));
}

void CacheStorageQuotaClient::DeleteOriginData(const url::Origin& origin,
                                               blink::mojom::StorageType type,
                                               DeletionCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!cache_manager_) {
    std::move(callback).Run(blink::mojom::QuotaStatusCode::kErrorAbort);
    return;
  }

  if (!DoesSupport(type)) {
    std::move(callback).Run(blink::mojom::QuotaStatusCode::kOk);
    return;
  }

  cache_manager_->DeleteOriginData(origin, std::move(callback));
}

bool CacheStorageQuotaClient::DoesSupport(
    blink::mojom::StorageType type) const {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  return type == blink::mojom::StorageType::kTemporary;
}

}  // namespace host
