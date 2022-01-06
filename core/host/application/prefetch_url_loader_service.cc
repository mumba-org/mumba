// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/prefetch_url_loader_service.h"

#include "base/feature_list.h"
#include "core/host/application/prefetch_url_loader.h"
#include "core/host/url_loader_factory_getter.h"
#include "core/host/host_client.h"
#include "core/host/application/application_contents.h"
#include "core/shared/common/client.h"
#include "core/shared/common/resource_type.h"
#include "core/shared/common/url_loader_throttle.h"
#include "core/shared/common/weak_wrapper_shared_url_loader_factory.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"

namespace host {

namespace {

std::vector<std::unique_ptr<common::URLLoaderThrottle>> CreateURLLoaderThrottlesInternal(
    const network::ResourceRequest& request,
    ResourceContext* resource_context) {//,
    //const base::RepeatingCallback<ApplicationContents*()>& wc_getter,
    //int frame_tree_node_id) {
  //DCHECK_CURRENTLY_ON(HostThread::IO);

  std::vector<std::unique_ptr<common::URLLoaderThrottle>> result;
  return result;
}

}

PrefetchURLLoaderService::PrefetchURLLoaderService(
    scoped_refptr<URLLoaderFactoryGetter> factory_getter)
    : loader_factory_getter_(std::move(factory_getter)) {}

void PrefetchURLLoaderService::InitializeResourceContext(
    ResourceContext* resource_context,
    scoped_refptr<net::URLRequestContextGetter> request_context_getter) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(!resource_context_);
  DCHECK(!request_context_getter_);
  resource_context_ = resource_context;
  request_context_getter_ = request_context_getter;
}

void PrefetchURLLoaderService::ConnectToService(
    int frame_tree_node_id,
    blink::mojom::PrefetchURLLoaderServiceRequest request) {
  if (!HostThread::CurrentlyOn(HostThread::IO)) {
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(&PrefetchURLLoaderService::ConnectToService, this,
                       frame_tree_node_id, std::move(request)));
    return;
  }
  service_bindings_.AddBinding(this, std::move(request), frame_tree_node_id);
}

void PrefetchURLLoaderService::CreateLoaderAndStart(
    network::mojom::URLLoaderRequest request,
    int32_t routing_id,
    int32_t request_id,
    uint32_t options,
    const network::ResourceRequest& resource_request,
    network::mojom::URLLoaderClientPtr client,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation,
    scoped_refptr<network::SharedURLLoaderFactory> network_loader_factory,
    base::RepeatingCallback<int(void)> frame_tree_node_id_getter) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK_EQ(common::RESOURCE_TYPE_PREFETCH, resource_request.resource_type);
  DCHECK(resource_context_);

  if (prefetch_load_callback_for_testing_)
    prefetch_load_callback_for_testing_.Run();

  // For now we strongly bind the loader to the request, while we can
  // also possibly make the new loader owned by the factory so that
  // they can live longer than the client (i.e. run in detached mode).
  // TODO(kinuko): Revisit this.
  mojo::MakeStrongBinding(
      std::make_unique<PrefetchURLLoader>(
          routing_id, request_id, options, frame_tree_node_id_getter,
          resource_request, std::move(client), traffic_annotation,
          std::move(network_loader_factory),
          base::BindRepeating(
              &PrefetchURLLoaderService::CreateURLLoaderThrottles, this,
              resource_request, frame_tree_node_id_getter),
          resource_context_, request_context_getter_),
      std::move(request));
}

PrefetchURLLoaderService::~PrefetchURLLoaderService() = default;

void PrefetchURLLoaderService::GetFactory(
    network::mojom::URLLoaderFactoryRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  loader_factory_bindings_.AddBinding(this, std::move(request),
                                      service_bindings_.dispatch_context());
}

void PrefetchURLLoaderService::CreateLoaderAndStart(
    network::mojom::URLLoaderRequest request,
    int32_t routing_id,
    int32_t request_id,
    uint32_t options,
    const network::ResourceRequest& resource_request,
    network::mojom::URLLoaderClientPtr client,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(base::FeatureList::IsEnabled(network::features::kNetworkService));
  int frame_tree_node_id = loader_factory_bindings_.dispatch_context();
  CreateLoaderAndStart(
      std::move(request), routing_id, request_id, options, resource_request,
      std::move(client), traffic_annotation,
      loader_factory_getter_->GetNetworkFactory(),
      base::BindRepeating([](int id) { return id; }, frame_tree_node_id));
}

void PrefetchURLLoaderService::Clone(
    network::mojom::URLLoaderFactoryRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  loader_factory_bindings_.AddBinding(
      this, std::move(request), loader_factory_bindings_.dispatch_context());
}

std::vector<std::unique_ptr<common::URLLoaderThrottle>>
PrefetchURLLoaderService::CreateURLLoaderThrottles(
    const network::ResourceRequest& request,
    base::RepeatingCallback<int(void)> frame_tree_node_id_getter) {
  if (!base::FeatureList::IsEnabled(network::features::kNetworkService) ||
      !request_context_getter_ ||
      !request_context_getter_->GetURLRequestContext())
    return std::vector<std::unique_ptr<common::URLLoaderThrottle>>();
  //int frame_tree_node_id = frame_tree_node_id_getter.Run();
  return CreateURLLoaderThrottlesInternal(
      request, resource_context_);//,
      //base::BindRepeating(&ApplicationContents::FromFrameTreeNodeId,
      //                    frame_tree_node_id),
      //nullptr /* navigation_ui_data */, frame_tree_node_id);
}

}  // namespace content
