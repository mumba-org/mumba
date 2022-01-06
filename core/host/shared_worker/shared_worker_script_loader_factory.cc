// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/shared_worker/shared_worker_script_loader_factory.h"

#include <memory>
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_provider_host.h"
#include "core/host/service_worker/service_worker_version.h"
#include "core/host/shared_worker/shared_worker_script_loader.h"
#include "core/host/url_loader_factory_getter.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "services/network/public/cpp/resource_response.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_provider_type.mojom.h"

namespace host {

SharedWorkerScriptLoaderFactory::SharedWorkerScriptLoaderFactory(
    ServiceWorkerContextWrapper* context,
    base::WeakPtr<ServiceWorkerProviderHost> service_worker_provider_host,
    ResourceContext* resource_context,
    scoped_refptr<URLLoaderFactoryGetter> loader_factory_getter)
    : service_worker_provider_host_(service_worker_provider_host),
      resource_context_(resource_context),
      loader_factory_getter_(loader_factory_getter) {
  DCHECK(common::ServiceWorkerUtils::IsServicificationEnabled());
  DCHECK_EQ(service_worker_provider_host_->provider_type(),
            blink::mojom::ServiceWorkerProviderType::kForSharedWorker);
}

SharedWorkerScriptLoaderFactory::~SharedWorkerScriptLoaderFactory() {}

void SharedWorkerScriptLoaderFactory::CreateLoaderAndStart(
    network::mojom::URLLoaderRequest request,
    int32_t routing_id,
    int32_t request_id,
    uint32_t options,
    const network::ResourceRequest& resource_request,
    network::mojom::URLLoaderClientPtr client,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  // Handle only the main script (RESOURCE_TYPE_SHARED_WORKER). Import scripts
  // should go to the network loader or controller.
  if (resource_request.resource_type != common::RESOURCE_TYPE_SHARED_WORKER) {
    mojo::ReportBadMessage(
        "SharedWorkerScriptLoaderFactory should only get requests for shared "
        "worker scripts");
    return;
  }

  // Create a SharedWorkerScriptLoader to load the script.
  mojo::MakeStrongBinding(
      std::make_unique<SharedWorkerScriptLoader>(
          routing_id, request_id, options, resource_request, std::move(client),
          service_worker_provider_host_, resource_context_,
          loader_factory_getter_, traffic_annotation),
      std::move(request));
}

void SharedWorkerScriptLoaderFactory::Clone(
    network::mojom::URLLoaderFactoryRequest request) {
  // This method is required to support synchronous requests, which shared
  // worker script requests are not.
  NOTIMPLEMENTED();
}

}  // namespace host
