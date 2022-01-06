// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_navigation_handle_core.h"

#include <utility>

#include "base/bind.h"
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_navigation_handle.h"
#include "core/host/service_worker/service_worker_provider_host.h"
#include "core/shared/common/service_worker/service_worker_types.h"
#include "core/host/host_thread.h"

namespace host {

ServiceWorkerNavigationHandleCore::ServiceWorkerNavigationHandleCore(
    base::WeakPtr<ServiceWorkerNavigationHandle> ui_handle,
    ServiceWorkerContextWrapper* context_wrapper)
    : context_wrapper_(context_wrapper), ui_handle_(ui_handle) {
  // The ServiceWorkerNavigationHandleCore is created on the UI thread but
  // should only be accessed from the IO thread afterwards.
  DCHECK_CURRENTLY_ON(HostThread::UI);
}

ServiceWorkerNavigationHandleCore::~ServiceWorkerNavigationHandleCore() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (precreated_host_.get() && context_wrapper_->context()) {
    context_wrapper_->context()->RemoveNavigationHandleCore(
        precreated_host_->provider_id());
  }
}

void ServiceWorkerNavigationHandleCore::DidPreCreateProviderHost(
    std::unique_ptr<ServiceWorkerProviderHost> precreated_host) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(precreated_host.get());
  DCHECK(context_wrapper_->context());

  precreated_host_ = std::move(precreated_host);
  context_wrapper_->context()->AddNavigationHandleCore(
      precreated_host_->provider_id(), this);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &ServiceWorkerNavigationHandle::DidCreateServiceWorkerProviderHost,
          ui_handle_, precreated_host_->provider_id()));
}

std::unique_ptr<ServiceWorkerProviderHost>
ServiceWorkerNavigationHandleCore::RetrievePreCreatedHost() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(precreated_host_);
  // Remove the ServiceWorkerNavigationHandleCore from the list of
  // ServiceWorkerNavigationHandleCores since it will no longer hold a
  // ServiceWorkerProviderHost.
  DCHECK(context_wrapper_->context());
  context_wrapper_->context()->RemoveNavigationHandleCore(
      precreated_host_->provider_id());
  return std::move(precreated_host_);
}

}  // namespace host
