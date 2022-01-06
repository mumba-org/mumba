// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/host_network_context.h"

#include "base/command_line.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial_params.h"
#include "base/task_scheduler/post_task.h"
#include "base/lazy_instance.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/base/logging_network_change_observer.h"
#include "net/base/network_change_notifier.h"
#include "net/dns/host_resolver.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/log/net_log.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/rpc/rpc_message_encoder.h"
#include "services/network/mojo_net_log.h"
#include "services/network/network_context.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/url_request_context_builder_mojo.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/url_loader.h"
#include "core/host/route/rpc_url_loader_factory.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/network_error_url_loader.h"
#include "core/host/route/rpc_url_loader.h"
#include "core/host/route/ipc_url_loader.h"
#include "core/host/global_routing_id.h"
#include "core/host/host_controller.h"
#include "core/host/host_thread.h"
#include "core/host/io_thread.h"

namespace host {

HostNetworkContext::HostNetworkContext(
  network::NetworkService* network_service,
  network::mojom::NetworkContextRequest request,
  network::mojom::NetworkContextParamsPtr params,
  std::unique_ptr<network::URLRequestContextBuilderMojo> builder):
   network::NetworkContext(
     network_service, 
     std::move(request), 
     std::move(params), 
     std::move(builder)),
     weak_factory_(this) {

}

HostNetworkContext::~HostNetworkContext() {

}

network::mojom::URLLoaderFactory* HostNetworkContext::CreateRpcURLLoaderFactory(
  scoped_refptr<base::SingleThreadTaskRunner> task_runner,
  ApplicationWindowHost* application_window_host,
  RouteRegistry* registry,
  std::unique_ptr<net::RpcMessageEncoder> encoder,
  network::mojom::URLLoaderFactoryRequest request) {
  
  std::unique_ptr<RpcURLLoaderFactory> factory = 
    std::make_unique<RpcURLLoaderFactory>(
      std::move(task_runner),
      weak_factory_.GetWeakPtr(),
      application_window_host,
      registry,
      std::move(encoder),
      std::move(request));
  RpcURLLoaderFactory* handle = factory.get();
  rpc_url_loader_factories_.emplace(std::move(factory));
  return handle;
}

network::mojom::URLLoaderFactory* HostNetworkContext::CreateRpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    int routing_id,
    int process_id,
    network::mojom::URLLoaderFactoryRequest request) {
  std::unique_ptr<RpcURLLoaderFactory> factory = 
    std::make_unique<RpcURLLoaderFactory>(
      std::move(task_runner),
      weak_factory_.GetWeakPtr(),
      registry,
      std::move(encoder),
      routing_id,
      process_id,
      std::move(request));
  RpcURLLoaderFactory* handle = factory.get();
  rpc_url_loader_factories_.emplace(std::move(factory));
  return handle;
}

network::mojom::URLLoaderFactory* HostNetworkContext::CreateIpcURLLoaderFactory(
  scoped_refptr<base::SingleThreadTaskRunner> task_runner,
  ApplicationWindowHost* application_window_host,
  Domain* domain,
  RouteRegistry* registry,
  network::mojom::URLLoaderFactoryRequest request) {
  
  std::unique_ptr<IpcURLLoaderFactory> factory = 
    std::make_unique<IpcURLLoaderFactory>(
      std::move(task_runner),
      weak_factory_.GetWeakPtr(),
      domain,
      application_window_host,
      registry,
      std::move(request));
  IpcURLLoaderFactory* handle = factory.get();
  ipc_url_loader_factories_.emplace(std::move(factory));
  return handle;
}

network::mojom::URLLoaderFactory* HostNetworkContext::CreateIpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    Domain* domain,
    RouteRegistry* registry,
    int routing_id,
    int process_id,
    network::mojom::URLLoaderFactoryRequest request) {
  std::unique_ptr<IpcURLLoaderFactory> factory = 
    std::make_unique<IpcURLLoaderFactory>(
      std::move(task_runner),
      weak_factory_.GetWeakPtr(),
      domain,
      registry,
      routing_id,
      process_id,
      std::move(request));
  IpcURLLoaderFactory* handle = factory.get();
  ipc_url_loader_factories_.emplace(std::move(factory));
  return handle;
}

network::mojom::URLLoaderFactory* HostNetworkContext::CreateApplicationURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    ApplicationWindowHost* application_window_host,
    Domain* domain,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    network::mojom::URLLoaderFactoryRequest request) {
  std::unique_ptr<ApplicationURLLoaderFactory> factory = 
    std::make_unique<ApplicationURLLoaderFactory>(
      std::move(task_runner),
      weak_factory_.GetWeakPtr(),
      application_window_host,
      domain,
      registry,
      std::move(encoder),
      std::move(request));
  ApplicationURLLoaderFactory* handle = factory.get();
  application_url_loader_factories_.emplace(std::move(factory));
  return handle;
}

network::mojom::URLLoaderFactory* HostNetworkContext::CreateApplicationURLLoaderFactory(
  scoped_refptr<base::SingleThreadTaskRunner> task_runner,
  Domain* domain,
  RouteRegistry* registry,
  std::unique_ptr<net::RpcMessageEncoder> encoder,
  int routing_id,
  int process_id,
  network::mojom::URLLoaderFactoryRequest request) {
  std::unique_ptr<ApplicationURLLoaderFactory> factory = 
    std::make_unique<ApplicationURLLoaderFactory>(
      std::move(task_runner),
      weak_factory_.GetWeakPtr(),
      domain,
      registry,
      std::move(encoder),
      routing_id,
      process_id,
      std::move(request));
  ApplicationURLLoaderFactory* handle = factory.get();
  application_url_loader_factories_.emplace(std::move(factory));
  return handle;
}

void HostNetworkContext::DestroyRpcURLLoaderFactory(
  RpcURLLoaderFactory* url_loader_factory) {
  auto it = rpc_url_loader_factories_.find(url_loader_factory);
  DCHECK(it != rpc_url_loader_factories_.end());
  rpc_url_loader_factories_.erase(it);
}

void HostNetworkContext::DestroyIpcURLLoaderFactory(
  IpcURLLoaderFactory* url_loader_factory) {
  auto it = ipc_url_loader_factories_.find(url_loader_factory);
  DCHECK(it != ipc_url_loader_factories_.end());
  ipc_url_loader_factories_.erase(it);
}

void HostNetworkContext::DestroyApplicationURLLoaderFactory(
  ApplicationURLLoaderFactory* url_loader_factory) {
  auto it = application_url_loader_factories_.find(url_loader_factory);
  DCHECK(it != application_url_loader_factories_.end());
  application_url_loader_factories_.erase(it);
}

}