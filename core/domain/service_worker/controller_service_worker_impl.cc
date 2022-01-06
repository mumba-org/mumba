// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/service_worker/controller_service_worker_impl.h"

#include "core/shared/common/service_worker/service_worker_utils.h"
#include "core/domain/service_worker/service_worker_context_client.h"

namespace domain {

ControllerServiceWorkerImpl::ControllerServiceWorkerImpl(
    common::mojom::ControllerServiceWorkerRequest request,
    base::WeakPtr<ServiceWorkerContextClient> context_client)
    : context_client_(std::move(context_client)) {
  CHECK(common::ServiceWorkerUtils::IsServicificationEnabled());
  bindings_.AddBinding(this, std::move(request));
}

ControllerServiceWorkerImpl::~ControllerServiceWorkerImpl() = default;

void ControllerServiceWorkerImpl::Clone(
    common::mojom::ControllerServiceWorkerRequest request) {
  bindings_.AddBinding(this, std::move(request));
}

void ControllerServiceWorkerImpl::DispatchFetchEvent(
    common::mojom::DispatchFetchEventParamsPtr params,
    common::mojom::ServiceWorkerFetchResponseCallbackPtr response_callback,
    DispatchFetchEventCallback callback) {
  DCHECK(context_client_);
  context_client_->DispatchOrQueueFetchEvent(
      std::move(params), std::move(response_callback), std::move(callback));
}

}  // namespace domain
