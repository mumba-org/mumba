// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_navigation_handle.h"

#include "base/bind.h"
#include "core/host/service_worker/service_worker_navigation_handle_core.h"
#include "core/shared/common/service_worker/service_worker_types.h"
#include "core/host/host_thread.h"

namespace host {

ServiceWorkerNavigationHandle::ServiceWorkerNavigationHandle(
    ServiceWorkerContextWrapper* context_wrapper)
    : service_worker_provider_host_id_(common::kInvalidServiceWorkerProviderId),
      weak_factory_(this) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  core_ = new ServiceWorkerNavigationHandleCore(weak_factory_.GetWeakPtr(),
                                                context_wrapper);
}

ServiceWorkerNavigationHandle::~ServiceWorkerNavigationHandle() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // Delete the ServiceWorkerNavigationHandleCore on the IO thread.
  HostThread::DeleteSoon(HostThread::IO, FROM_HERE, core_);
}

void ServiceWorkerNavigationHandle::DidCreateServiceWorkerProviderHost(
    int service_worker_provider_host_id) {
  base::AutoLock lock(observers_lock_);
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //DLOG(INFO) << "ServiceWorkerNavigationHandle::DidCreateServiceWorkerProviderHost: service_worker_provider_host_id = " << service_worker_provider_host_id;
  service_worker_provider_host_id_ = service_worker_provider_host_id;
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it; 
    observer->OnCreateServiceWorkerProviderHost(service_worker_provider_host_id);
  }
}

void ServiceWorkerNavigationHandle::AddObserver(Observer* observer) {
  base::AutoLock lock(observers_lock_);
  observers_.push_back(observer);
}

void ServiceWorkerNavigationHandle::RemoveObserver(Observer* observer) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

}  // namespace host
