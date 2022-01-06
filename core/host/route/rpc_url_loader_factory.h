// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_HOST_APPLICATION_RPC_URL_LOADER_FACTORY_H_
#define CORE_HOST_APPLICATION_RPC_URL_LOADER_FACTORY_H_

#include "base/containers/unique_ptr_adapters.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/containers/flat_set.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/network_service.h"
#include "core/host/host_thread.h"
#include "core/host/application/application_contents_observer.h"

namespace network {
class NetworkContext;
class ResourceSchedulerClient;
}

namespace net {
class RpcMessageEncoder;  
}

namespace host {
class RpcURLLoader;
class RouteRegistry;
class HostNetworkContext;
// This class is an implementation of mojom::URLLoaderFactory that
// creates a mojom::URLLoader.
// A URLLoaderFactory has a pointer to ResourceSchedulerClient. A
// ResourceSchedulerClient is associated with cloned
// NetworkServiceURLLoaderFactories. Roughly one URLLoaderFactory
// is created for one frame in render process, so it means ResourceScheduler
// works on each frame.
// A URLLoaderFactory can be created with null ResourceSchedulerClient, in which
// case requests constructed by the factory will not be throttled.
//
// URLLoaderFactories own all the URLLoaders they were used to create. Once
// there are no live Mojo pipes to a URLLoaderFactory, and all URLLoaders it was
// used to created have been destroyed, it will tell the NetworkContext that
// owns it to destroy it.
class RpcURLLoaderFactory : public network::mojom::URLLoaderFactory {
 public:
  RpcURLLoaderFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::WeakPtr<HostNetworkContext> context,
      ApplicationWindowHost* application_window_host,
      RouteRegistry* route_registry,
      std::unique_ptr<net::RpcMessageEncoder> encoder,
      network::mojom::URLLoaderFactoryRequest request);
  
  RpcURLLoaderFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::WeakPtr<HostNetworkContext> context,
      RouteRegistry* route_registry,
      std::unique_ptr<net::RpcMessageEncoder> encoder,
      int routing_id,
      int process_id,
      network::mojom::URLLoaderFactoryRequest request);

  ~RpcURLLoaderFactory() override;

  //network::mojom::NetworkContext* context() const {
  //  return context_;
  //}

  // mojom::URLLoaderFactory implementation.
  void CreateLoaderAndStart(network::mojom::URLLoaderRequest request,
                            int32_t routing_id,
                            int32_t request_id,
                            uint32_t options,
                            const network::ResourceRequest& url_request,
                            network::mojom::URLLoaderClientPtr client,
                            const net::MutableNetworkTrafficAnnotationTag&
                                traffic_annotation) override;
  void Clone(network::mojom::URLLoaderFactoryRequest request) override;

  void DestroyURLLoader(network::mojom::URLLoader* url_loader);

  void OnApplicationWindowDeleted();

  ApplicationWindowHost* application_window_host() const {
    return application_window_host_;
  }

  static constexpr int kMaxKeepaliveConnections = 256;
  static constexpr int kMaxKeepaliveConnectionsPerProcess = 20;
  static constexpr int kMaxKeepaliveConnectionsPerProcessForFetchAPI = 10;

 private:
  class ContentsObserver;
  // If |binding_set_| and |url_loaders_| are both empty, tells the
  // NetworkContext to destroy |this|.
  void DeleteIfNeeded();
  
  void CreateLoaderAndStartImpl(network::mojom::URLLoaderRequest request,
                                int32_t routing_id,
                                int32_t request_id,
                                uint32_t options,
                                const network::ResourceRequest& url_request,
                                network::mojom::URLLoaderClientPtr client,
                                const net::MutableNetworkTrafficAnnotationTag&
                                 traffic_annotation);

  void ApplicationWindowDeletedOnIOThread();

  base::WeakPtr<HostNetworkContext> context_;
  ApplicationWindowHost* application_window_host_;
  RouteRegistry* route_registry_;
  std::unique_ptr<net::RpcMessageEncoder> encoder_;
  std::unique_ptr<ContentsObserver, HostThread::DeleteOnUIThread> contents_observer_;
  uint32_t routing_id_;
  uint32_t process_id_;
  //scoped_refptr<network::ResourceSchedulerClient> resource_scheduler_client_;

  scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner_;

  mojo::BindingSet<network::mojom::URLLoaderFactory> binding_set_;
  std::set<std::unique_ptr<RpcURLLoader>, base::UniquePtrComparator> url_loaders_;

  net::URLRequestContext* url_request_context_;

  base::WeakPtrFactory<RpcURLLoaderFactory> weak_factory_;
 
  DISALLOW_COPY_AND_ASSIGN(RpcURLLoaderFactory);
};

// // Create a URLLoaderFactory for loading resources matching the specified
// // |scheme| and also from a "pseudo host" matching one in |allowed_hosts|.
// CONTENT_EXPORT network::mojom::URLLoaderFactory*
// CreateRpcURLLoaderFactory(
//       ApplicationWindowHost* application_window_host,
//       RouteRegistry* place_registry,
//       std::unique_ptr<net::RpcMessageEncoder> encoder,
//       //network::mojom::NetworkContext* context,
//       //scoped_refptr<network::ResourceSchedulerClient> resource_scheduler_client,
//       network::mojom::URLLoaderFactoryRequest request);

// // CONTENT_EXPORT network::mojom::URLLoaderFactoryPtr CreateRpcURLLoaderFactoryBinding(
// //       ApplicationWindowHost* application_window_host,
// //       network::NetworkContext* context,
// //       scoped_refptr<network::ResourceSchedulerClient> resource_scheduler_client,
// //       network::mojom::URLLoaderFactoryRequest request);


}  // namespace host

#endif  // SERVICES_NETWORK_URL_LOADER_FACTORY_H_
