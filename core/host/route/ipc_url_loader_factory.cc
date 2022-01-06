// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/ipc_url_loader_factory.h"

#include <map>

#include "base/logging.h"
#include "base/lazy_instance.h"
#include "base/task_scheduler/post_task.h"
#include "base/test/scoped_task_environment.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/network_error_url_loader.h"
#include "core/host/application/domain.h"
#include "core/host/route/ipc_url_loader.h"
#include "services/network/network_context.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/url_loader.h"
#include "core/host/global_routing_id.h"
#include "core/host/host_controller.h"
#include "core/host/host_thread.h"
#include "core/host/io_thread.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
#include "core/host/net/host_network_context.h"
#include "net/rpc/rpc_message_encoder.h"
#include "net/rpc/rpc_network_session.h"
#include "net/url_request/url_request_context.h"

namespace host {

constexpr int IpcURLLoaderFactory::kMaxKeepaliveConnections;
constexpr int IpcURLLoaderFactory::kMaxKeepaliveConnectionsPerProcess;
constexpr int IpcURLLoaderFactory::kMaxKeepaliveConnectionsPerProcessForFetchAPI;

class IpcURLLoaderFactory::ContentsObserver : public ApplicationContentsObserver {
public:
  ContentsObserver(
    base::WeakPtr<IpcURLLoaderFactory> factory,
    ApplicationContents* contents): 
      ApplicationContentsObserver(contents), 
      factory_(std::move(factory))  {}
  
  ~ContentsObserver() override {}
  
  void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) override {
    HostThread::PostTask(
     HostThread::IO, 
     FROM_HERE, 
     base::BindOnce(&IpcURLLoaderFactory::ApplicationWindowDeletedOnIOThread, 
      factory_));
  }

private: 
  base::WeakPtr<IpcURLLoaderFactory> factory_;
};

IpcURLLoaderFactory::IpcURLLoaderFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::WeakPtr<HostNetworkContext> context,
      Domain* domain,
      RouteRegistry* route_registry,
      int routing_id,
      int process_id,
      network::mojom::URLLoaderFactoryRequest request):
      domain_(domain),
      application_window_host_(nullptr),
      route_registry_(route_registry),
      routing_id_(routing_id),
      process_id_(process_id),
      loader_task_runner_(task_runner),
      url_request_context_(nullptr),
      route_task_runner_(
        base::CreateSequencedTaskRunnerWithTraits({
          base::MayBlock(), 
          base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN
      })),
      weak_factory_(this) {
  if (context) {
    context_ = std::move(context);
  }
  binding_set_.AddBinding(this, std::move(request));
  binding_set_.set_connection_error_handler(base::BindRepeating(
      &IpcURLLoaderFactory::DeleteIfNeeded, base::Unretained(this)));
  
  if (context_) {
    url_request_context_ = context_->url_request_context();   
  }
  
  // if (url_request_context_) {
  //   // add the rpc encoder
  //   net::RpcNetworkSession* session = url_request_context_->rpc_network_session();
  //   session->AddEncoder(encoder_.get());
  // }
}

IpcURLLoaderFactory::IpcURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    base::WeakPtr<HostNetworkContext> context,
    Domain* domain,
    ApplicationWindowHost* application_window_host,
    RouteRegistry* route_registry,
    network::mojom::URLLoaderFactoryRequest request)
    : domain_(domain),
      application_window_host_(application_window_host),
      route_registry_(route_registry),
      routing_id_(application_window_host->GetRoutingID()),
      process_id_(application_window_host->GetProcess()->GetID()),
      loader_task_runner_(task_runner),
      url_request_context_(nullptr),
      route_task_runner_(
        base::CreateSequencedTaskRunnerWithTraits({
          base::MayBlock(), 
          base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN
      })),
      weak_factory_(this) {
  binding_set_.AddBinding(this, std::move(request));
  binding_set_.set_connection_error_handler(base::BindRepeating(
      &IpcURLLoaderFactory::DeleteIfNeeded, base::Unretained(this)));
  if (context) {
    context_ = std::move(context);
  }

  if (context_) {
    url_request_context_ = context_->url_request_context();   
  }
  
  contents_observer_.reset(new ContentsObserver(
        weak_factory_.GetWeakPtr(),
        ApplicationContents::FromApplicationWindowHost(application_window_host)));

  // add the rpc encoder
  // if (url_request_context_) {
  //   net::RpcNetworkSession* session = url_request_context_->rpc_network_session();
  //   session->AddEncoder(encoder_.get());
  // }
}

IpcURLLoaderFactory::~IpcURLLoaderFactory() {
  // remove the encoder
  // if (context_) {
  //   net::RpcNetworkSession* session = context_->url_request_context()->rpc_network_session();
  //   session->RemoveEncoder(encoder_.get());
  // }
  loader_task_runner_ = nullptr;
}

void IpcURLLoaderFactory::CreateLoaderAndStart(
    network::mojom::URLLoaderRequest request,
    int32_t routing_id,
    int32_t request_id,
    uint32_t options,
    const network::ResourceRequest& url_request,
    network::mojom::URLLoaderClientPtr client,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {

  loader_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(
      &IpcURLLoaderFactory::CreateLoaderAndStartImpl,
      base::Unretained(this),
      base::Passed(std::move(request)),
      routing_id,
      request_id,
      options,
      url_request,
      base::Passed(std::move(client)),
      traffic_annotation));
}

void IpcURLLoaderFactory::Clone(network::mojom::URLLoaderFactoryRequest request) {
  binding_set_.AddBinding(this, std::move(request));
}

void IpcURLLoaderFactory::DestroyURLLoader(network::mojom::URLLoader* url_loader) {
  auto it = url_loaders_.find(static_cast<IpcURLLoader*>(url_loader));
  DCHECK(it != url_loaders_.end());
  url_loaders_.erase(it);
  DeleteIfNeeded();
}

void IpcURLLoaderFactory::DeleteIfNeeded() {
  
}

void IpcURLLoaderFactory::OnApplicationWindowDeleted() {
  HostThread::PostTask(
     HostThread::IO, 
     FROM_HERE, 
     base::BindOnce(&IpcURLLoaderFactory::ApplicationWindowDeletedOnIOThread, 
      weak_factory_.GetWeakPtr()));
}

void IpcURLLoaderFactory::ApplicationWindowDeletedOnIOThread() {
  
  if (context_) {
    context_->DestroyIpcURLLoaderFactory(this);
  }
}

void IpcURLLoaderFactory::CreateLoaderAndStartImpl(
  network::mojom::URLLoaderRequest request,
  int32_t routing_id,
  int32_t request_id,
  uint32_t options,
  const network::ResourceRequest& url_request,
  network::mojom::URLLoaderClientPtr client,
  const net::MutableNetworkTrafficAnnotationTag&
    traffic_annotation) {
  DCHECK(!url_request.download_to_file);
  bool report_raw_headers = false;
  // if (url_request.report_raw_headers) {
  //   const network::NetworkService* service = context_->network_service();
  //   report_raw_headers = service && service->HasRawHeadersAccess(process_id_);
  //   if (!report_raw_headers)
  //     DLOG(ERROR) << "Denying raw headers request by process " << process_id_;
  // }

  //network::mojom::NetworkServiceClient* network_service_client = nullptr;
  //if (context_->network_service()) {
  //  network_service_client = context_->network_service()->client();
  //}

  // resolve entry now..
  RouteEntry* route_entry = route_registry_->model()->GetEntry(url_request.url);

  url_loaders_.insert(
    std::unique_ptr<IpcURLLoader>(
      new IpcURLLoader(
        loader_task_runner_,
        route_task_runner_,
        url_request_context_,
        domain_,
        route_registry_,
        route_entry,
        base::BindOnce(&IpcURLLoaderFactory::DestroyURLLoader,
                     base::Unretained(this)),
        std::move(request), 
        options, 
        url_request, 
        report_raw_headers,
        std::move(client),
        static_cast<net::NetworkTrafficAnnotationTag>(traffic_annotation),
        process_id_, 
        request_id)));
}

}  // namespace host
