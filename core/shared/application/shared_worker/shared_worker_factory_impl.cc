// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/shared_worker/shared_worker_factory_impl.h"

#include "base/memory/ptr_util.h"
#include "core/shared/application/shared_worker/embedded_shared_worker_stub.h"
#include "mojo/public/cpp/bindings/strong_binding.h"

namespace application {

// static
void SharedWorkerFactoryImpl::Create(
    common::mojom::SharedWorkerFactoryRequest request) {
  mojo::MakeStrongBinding<common::mojom::SharedWorkerFactory>(
      base::WrapUnique(new SharedWorkerFactoryImpl()), std::move(request));
}

SharedWorkerFactoryImpl::SharedWorkerFactoryImpl() {}

void SharedWorkerFactoryImpl::CreateSharedWorker(
    common::mojom::SharedWorkerInfoPtr info,
    bool pause_on_start,
    const base::UnguessableToken& devtools_worker_token,
    blink::mojom::WorkerContentSettingsProxyPtr content_settings,
    common::mojom::ServiceWorkerProviderInfoForSharedWorkerPtr
        service_worker_provider_info,
    network::mojom::URLLoaderFactoryAssociatedPtrInfo
        script_loader_factory_ptr_info,
    common::mojom::SharedWorkerHostPtr host,
    common::mojom::SharedWorkerRequest request,
    service_manager::mojom::InterfaceProviderPtr interface_provider) {
  // Bound to the lifetime of the underlying blink::WebSharedWorker instance.
  new EmbeddedSharedWorkerStub(
      std::move(info), pause_on_start, devtools_worker_token,
      std::move(content_settings), std::move(service_worker_provider_info),
      std::move(script_loader_factory_ptr_info), std::move(host),
      std::move(request), std::move(interface_provider));
}

}  // namespace content
