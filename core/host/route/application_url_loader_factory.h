// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_HOST_APPLICATION_APPLICATION_URL_LOADER_FACTORY_H_
#define CORE_HOST_APPLICATION_APPLICATION_URL_LOADER_FACTORY_H_

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
class URLLoader;
}

namespace net {
class RpcMessageEncoder;
}

namespace host {
class IpcURLLoader;
class RpcURLLoader;
class RouteRegistry;
class HostNetworkContext;
class Domain;

enum class UrlLoaderTransport {
  kUNDEFINED = 0,
  kIPC = 1,
  kRPC = 2,
  kHTTP = 3
};

class ApplicationURLLoaderFactory : public network::mojom::URLLoaderFactory {
 public:
  ApplicationURLLoaderFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::WeakPtr<HostNetworkContext> context,
      ApplicationWindowHost* application_window_host,
      Domain* domain,
      RouteRegistry* route_registry,
      std::unique_ptr<net::RpcMessageEncoder> encoder,
      network::mojom::URLLoaderFactoryRequest request);
  
  ApplicationURLLoaderFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::WeakPtr<HostNetworkContext> context,
      Domain* domain,
      RouteRegistry* route_registry,
      std::unique_ptr<net::RpcMessageEncoder> encoder,
      int routing_id,
      int process_id,
      network::mojom::URLLoaderFactoryRequest request);

  ~ApplicationURLLoaderFactory() override;

  UrlLoaderTransport last_transport() const {
    return last_transport_;
  }

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
  void DestroyURLLoaderImpl(network::URLLoader* url_loader);

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

  UrlLoaderTransport last_transport_;
  base::WeakPtr<HostNetworkContext> context_;
  ApplicationWindowHost* application_window_host_;
  Domain* domain_;
  RouteRegistry* route_registry_;
  std::unique_ptr<net::RpcMessageEncoder> encoder_;
  std::unique_ptr<ContentsObserver, HostThread::DeleteOnUIThread> contents_observer_;
  uint32_t routing_id_;
  uint32_t process_id_;
  scoped_refptr<network::ResourceSchedulerClient> resource_scheduler_client_;

  scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner_;

  mojo::BindingSet<network::mojom::URLLoaderFactory> binding_set_;
  std::set<std::unique_ptr<network::mojom::URLLoader>, base::UniquePtrComparator> url_loaders_;
  
  net::URLRequestContext* url_request_context_;

  scoped_refptr<base::SequencedTaskRunner> route_task_runner_;

  //int next_request_id_;

  base::WeakPtrFactory<ApplicationURLLoaderFactory> weak_factory_;
 
  DISALLOW_COPY_AND_ASSIGN(ApplicationURLLoaderFactory);
};


}  // namespace host

#endif