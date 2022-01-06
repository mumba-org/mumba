// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/application_url_loader_factory.h"

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
#include "core/host/route/ipc_url_loader.h"
#include "core/host/route/rpc_url_loader.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "services/network/network_context.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/url_loader.h"
#include "services/network/url_loader_factory.h"
#include "core/host/global_routing_id.h"
#include "core/host/host_controller.h"
#include "core/host/host_thread.h"
#include "core/host/io_thread.h"
#include "core/host/net/host_network_context.h"
#include "net/rpc/rpc_message_encoder.h"
#include "net/rpc/rpc_network_session.h"
#include "net/url_request/url_request_context.h"

namespace host {

constexpr int ApplicationURLLoaderFactory::kMaxKeepaliveConnections;
constexpr int ApplicationURLLoaderFactory::kMaxKeepaliveConnectionsPerProcess;
constexpr int ApplicationURLLoaderFactory::kMaxKeepaliveConnectionsPerProcessForFetchAPI;

class ApplicationURLLoaderFactory::ContentsObserver : public ApplicationContentsObserver {
public:
  ContentsObserver(
    base::WeakPtr<ApplicationURLLoaderFactory> factory,
    ApplicationContents* contents): 
      ApplicationContentsObserver(contents), 
      factory_(std::move(factory))  {}
  
  ~ContentsObserver() override {}
  
  void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) override {
    HostThread::PostTask(
     HostThread::IO, 
     FROM_HERE, 
     base::BindOnce(&ApplicationURLLoaderFactory::ApplicationWindowDeletedOnIOThread, 
      factory_));
  }

private: 
  base::WeakPtr<ApplicationURLLoaderFactory> factory_;
};

ApplicationURLLoaderFactory::ApplicationURLLoaderFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::WeakPtr<HostNetworkContext> context,
      Domain* domain,
      RouteRegistry* route_registry,
      std::unique_ptr<net::RpcMessageEncoder> encoder,
      int routing_id,
      int process_id,
      network::mojom::URLLoaderFactoryRequest request):
      last_transport_(UrlLoaderTransport::kUNDEFINED),
      application_window_host_(nullptr),
      domain_(domain),
      route_registry_(route_registry),
      encoder_(std::move(encoder)),
      routing_id_(routing_id),
      process_id_(process_id),
      loader_task_runner_(task_runner),
      url_request_context_(nullptr),
      route_task_runner_(
        base::CreateSequencedTaskRunnerWithTraits({
          base::MayBlock(), 
          base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN
      })),
      //next_request_id_(0),
      weak_factory_(this) {
  if (context) {
    context_ = std::move(context);
  }
  binding_set_.AddBinding(this, std::move(request));
  binding_set_.set_connection_error_handler(base::BindRepeating(
      &ApplicationURLLoaderFactory::DeleteIfNeeded, base::Unretained(this)));
  
  if (context_) {
    url_request_context_ = context_->url_request_context();   
  }
  
  if (url_request_context_) {
    // add the rpc encoder
    net::RpcNetworkSession* session = url_request_context_->rpc_network_session();
    session->AddEncoder(encoder_.get());
  }

  resource_scheduler_client_ = new network::ResourceSchedulerClient(
    process_id_, 
    routing_id_, 
    context->resource_scheduler(),
    nullptr /* network quality estimator*/);
}

ApplicationURLLoaderFactory::ApplicationURLLoaderFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    base::WeakPtr<HostNetworkContext> context,
    ApplicationWindowHost* application_window_host,
    Domain* domain,
    RouteRegistry* route_registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder,
    network::mojom::URLLoaderFactoryRequest request)
    : last_transport_(UrlLoaderTransport::kUNDEFINED),
      application_window_host_(application_window_host),
      domain_(domain),
      route_registry_(route_registry),
      encoder_(std::move(encoder)),
      routing_id_(application_window_host->GetRoutingID()),
      process_id_(application_window_host->GetProcess()->GetID()),
      loader_task_runner_(task_runner),
      url_request_context_(nullptr),
      route_task_runner_(
        base::CreateSequencedTaskRunnerWithTraits({
          base::MayBlock(), 
          base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN
      })),
      //next_request_id_(0),
      weak_factory_(this) {
  binding_set_.AddBinding(this, std::move(request));
  binding_set_.set_connection_error_handler(base::BindRepeating(
      &ApplicationURLLoaderFactory::DeleteIfNeeded, base::Unretained(this)));
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
  if (url_request_context_) {
    net::RpcNetworkSession* session = url_request_context_->rpc_network_session();
    session->AddEncoder(encoder_.get());
  }
}

ApplicationURLLoaderFactory::~ApplicationURLLoaderFactory() {
  // remove the encoder
  if (context_) {
    net::RpcNetworkSession* session = context_->url_request_context()->rpc_network_session();
    if (session) {
      session->RemoveEncoder(encoder_.get());
    }
  }
  loader_task_runner_ = nullptr;
}

void ApplicationURLLoaderFactory::CreateLoaderAndStart(
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
      &ApplicationURLLoaderFactory::CreateLoaderAndStartImpl,
      base::Unretained(this),
      base::Passed(std::move(request)),
      routing_id,
      request_id,
      options,
      url_request,
      base::Passed(std::move(client)),
      traffic_annotation));
}

void ApplicationURLLoaderFactory::Clone(network::mojom::URLLoaderFactoryRequest request) {
  binding_set_.AddBinding(this, std::move(request));
}

void ApplicationURLLoaderFactory::DestroyURLLoader(network::mojom::URLLoader* url_loader) {
  auto it = url_loaders_.find(url_loader);
  DCHECK(it != url_loaders_.end());
  url_loaders_.erase(it);
  DeleteIfNeeded();
}

void ApplicationURLLoaderFactory::DestroyURLLoaderImpl(network::URLLoader* url_loader) {
  DestroyURLLoader(url_loader);
}

void ApplicationURLLoaderFactory::DeleteIfNeeded() {
  
}

void ApplicationURLLoaderFactory::OnApplicationWindowDeleted() {
  HostThread::PostTask(
     HostThread::IO, 
     FROM_HERE, 
     base::BindOnce(&ApplicationURLLoaderFactory::ApplicationWindowDeletedOnIOThread, 
      weak_factory_.GetWeakPtr()));
}

void ApplicationURLLoaderFactory::ApplicationWindowDeletedOnIOThread() {
  
  if (context_) {
    context_->DestroyApplicationURLLoaderFactory(this);
  }
}

void ApplicationURLLoaderFactory::CreateLoaderAndStartImpl(
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
  std::unique_ptr<network::mojom::URLLoader> loader;
  // if (url_request.report_raw_headers) {
  //   const network::NetworkService* service = context_->network_service();
  //   report_raw_headers = service && service->HasRawHeadersAccess(process_id_);
  //   if (!report_raw_headers)
  //     DLOG(ERROR) << "Denying raw headers request by process " << process_id_;
  // }

  //network::mojom::NetworkServiceClient* network_service_client = nullptr;
  //if (context_->network_service()) {
  //  network_service_client = context_->network_service()->client();
  //

  // resolve entry now..
  RouteEntry* route_entry = route_registry_->model()->GetEntry(url_request.url);
  // DLOG(INFO) << 
  //   url_request.url << " entry: '" << 
  //   route_entry->name() << "' transport: " << route_entry->transport_type();
  if (!route_entry) {
    LOG(ERROR) << "no route entry found for url " << url_request.url << ". failed to create the necessary url loader for it";
    return;
  }


  if (route_entry->transport_type() == common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_IPC) {
    last_transport_ = UrlLoaderTransport::kIPC;
    loader.reset(
        new IpcURLLoader(
          loader_task_runner_,
          route_task_runner_,
          url_request_context_,
          domain_,
          route_registry_,
          route_entry,
          base::BindOnce(&ApplicationURLLoaderFactory::DestroyURLLoader,
                       base::Unretained(this)),
          std::move(request), 
          options, 
          url_request, 
          report_raw_headers,
          std::move(client),
          static_cast<net::NetworkTrafficAnnotationTag>(traffic_annotation),
          process_id_, 
          request_id));
  } else if (route_entry->transport_type() == common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_RPC) {
    last_transport_ = UrlLoaderTransport::kRPC;
    loader.reset(
        new RpcURLLoader(
          loader_task_runner_,
          url_request_context_,
          route_registry_,
          route_entry,
          base::BindOnce(&ApplicationURLLoaderFactory::DestroyURLLoader,
                       base::Unretained(this)),
          std::move(request), 
          options, 
          url_request, 
          report_raw_headers,
          std::move(client),
          static_cast<net::NetworkTrafficAnnotationTag>(traffic_annotation),
          process_id_, 
          request_id));
  } else if (route_entry->transport_type() == common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_HTTP) {
    last_transport_ = UrlLoaderTransport::kHTTP;

    network::mojom::NetworkServiceClient* network_service_client = nullptr;
    base::WeakPtr<network::KeepaliveStatisticsRecorder> keepalive_statistics_recorder;
    if (context_->network_service()) {
      network_service_client = context_->network_service()->client();
      keepalive_statistics_recorder = context_->network_service()
                                        ->keepalive_statistics_recorder()
                                        ->AsWeakPtr();
    }
    loader.reset(
      new network::URLLoader(
        context_->url_request_context(), 
        network_service_client,
        base::BindOnce(&ApplicationURLLoaderFactory::DestroyURLLoaderImpl,
                        base::Unretained(this)),
        std::move(request), 
        options, 
        url_request, 
        report_raw_headers,
        std::move(client),
        static_cast<net::NetworkTrafficAnnotationTag>(traffic_annotation),
        process_id_, 
        request_id, 
        resource_scheduler_client_,
        std::move(keepalive_statistics_recorder)));
  } 
  DCHECK(loader);
  url_loaders_.insert(std::move(loader));
}

}  // namespace host
