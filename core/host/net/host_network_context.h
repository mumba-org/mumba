// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_HOST_NETWORK_CONTEXT_H_
#define MUMBA_HOST_NET_HOST_NETWORK_CONTEXT_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "services/network/network_context.h"
#include "core/host/route/rpc_url_loader_factory.h"
#include "core/host/route/ipc_url_loader_factory.h"
#include "core/host/route/application_url_loader_factory.h"

namespace net {
class RpcMessageEncoder;  
}

namespace host {
class ApplicationWindowHost;
class RouteRegistry;

class HostNetworkContext : public network::NetworkContext {
public:
  HostNetworkContext(network::NetworkService* network_service,
                     network::mojom::NetworkContextRequest request,
                     network::mojom::NetworkContextParamsPtr params,
                     std::unique_ptr<network::URLRequestContextBuilderMojo> builder);
  
  ~HostNetworkContext() override;

  network::mojom::URLLoaderFactory* CreateRpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner,
    ApplicationWindowHost* application_window_host,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    network::mojom::URLLoaderFactoryRequest request);

  network::mojom::URLLoaderFactory* CreateRpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    int routing_id,
    int process_id,
    network::mojom::URLLoaderFactoryRequest request);

  network::mojom::URLLoaderFactory* CreateIpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner,
    ApplicationWindowHost* application_window_host,
    Domain* domain,
    RouteRegistry* registry,
    network::mojom::URLLoaderFactoryRequest request);

  network::mojom::URLLoaderFactory* CreateIpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner,
    Domain* domain,
    RouteRegistry* registry,
    int routing_id,
    int process_id,
    network::mojom::URLLoaderFactoryRequest request);  

  network::mojom::URLLoaderFactory* CreateApplicationURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner,
    ApplicationWindowHost* application_window_host,
    Domain* domain,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    network::mojom::URLLoaderFactoryRequest request);

  network::mojom::URLLoaderFactory* CreateApplicationURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> loader_task_runner,
    Domain* domain,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    int routing_id,
    int process_id,
    network::mojom::URLLoaderFactoryRequest request);  
  
  void DestroyRpcURLLoaderFactory(
    RpcURLLoaderFactory* url_loader_factory);

  void DestroyIpcURLLoaderFactory(
    IpcURLLoaderFactory* url_loader_factory);

  void DestroyApplicationURLLoaderFactory(
    ApplicationURLLoaderFactory* url_loader_factory);

private:

  std::set<std::unique_ptr<RpcURLLoaderFactory>, base::UniquePtrComparator>
      rpc_url_loader_factories_;

  std::set<std::unique_ptr<IpcURLLoaderFactory>, base::UniquePtrComparator>
      ipc_url_loader_factories_;

  std::set<std::unique_ptr<ApplicationURLLoaderFactory>, base::UniquePtrComparator>
      application_url_loader_factories_;        

  base::WeakPtrFactory<HostNetworkContext> weak_factory_;
};

}

#endif