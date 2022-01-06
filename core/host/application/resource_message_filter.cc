// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/resource_message_filter.h"

#include "base/feature_list.h"
#include "base/logging.h"
#include "core/host/appcache/chrome_appcache_service.h"
#include "core/host/blob_storage/chrome_blob_storage_context.h"
//#include "core/host/frame_host/render_frame_host_impl.h"
#include "core/host/application/prefetch_url_loader_service.h"
#include "core/host/application/resource_dispatcher_host.h"
#include "core/host/application/resource_requester_info.h"
#include "core/host/application/url_loader_factory_impl.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/navigation_controller.h"
#include "core/host/net/host_network_context.h"
#include "core/host/route/route_entry.h"
#include "core/host/route/route_controller.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/shared/common/resource_messages.h"
#include "core/host/host_thread.h"
#include "core/host/application/resource_context.h"
//#include "core/shared/common/content_features.h"
#include "core/shared/common/weak_wrapper_shared_url_loader_factory.h"
#include "core/host/route/rpc_url_loader_factory.h"
#include "services/network/cors/cors_url_loader_factory.h"
#include "services/network/public/cpp/features.h"
#include "storage/host/fileapi/file_system_context.h"

namespace host {
namespace {
network::mojom::URLLoaderFactory* g_test_factory;
ResourceMessageFilter* g_current_filter;

// int GetFrameTreeNodeId(int render_process_host_id, int render_frame_host_id) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   // RenderFrameHost* render_frame_host =
//   //     RenderFrameHost::FromID(render_process_host_id, render_frame_host_id);
//   // return render_frame_host ? render_frame_host->GetFrameTreeNodeId() : -1;
//   return -1;
// }

}  // namespace

ResourceMessageFilter::ResourceMessageFilter(
    int child_id,
    ChromeAppCacheService* appcache_service,
    ChromeBlobStorageContext* blob_storage_context,
    storage::FileSystemContext* file_system_context,
    ServiceWorkerContextWrapper* service_worker_context,
    PrefetchURLLoaderService* prefetch_url_loader_service,
    const GetContextsCallback& get_contexts_callback,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_thread_runner)
    : HostMessageFilter(ResourceMsgStart),
      HostAssociatedInterface<network::mojom::URLLoaderFactory>(this, this),
      is_channel_closed_(false),
      requester_info_(
          ResourceRequesterInfo::CreateForRenderer(child_id,
                                                   appcache_service,
                                                   blob_storage_context,
                                                   file_system_context,
                                                   service_worker_context,
                                                   get_contexts_callback)),
      url_loader_factory_(nullptr),
      prefetch_url_loader_service_(prefetch_url_loader_service),
      io_thread_task_runner_(io_thread_runner),
      registry_(nullptr),
      routing_id_(-1),
      process_id_(child_id),
      weak_ptr_factory_(this) {}


ResourceMessageFilter::ResourceMessageFilter(
    ChromeAppCacheService* appcache_service,
    ChromeBlobStorageContext* blob_storage_context,
    storage::FileSystemContext* file_system_context,
    ServiceWorkerContextWrapper* service_worker_context,
    PrefetchURLLoaderService* prefetch_url_loader_service,
    const GetContextsCallback& get_contexts_callback,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_thread_runner,
    RouteRegistry* registry,
    int process_id): 
      HostMessageFilter(ResourceMsgStart),
      HostAssociatedInterface<network::mojom::URLLoaderFactory>(this, this),
      is_channel_closed_(false),
      requester_info_(
          ResourceRequesterInfo::CreateForRenderer(process_id,
                                                   appcache_service,
                                                   blob_storage_context,
                                                   file_system_context,
                                                   service_worker_context,
                                                   get_contexts_callback)),
      url_loader_factory_(nullptr),
      prefetch_url_loader_service_(prefetch_url_loader_service),
      io_thread_task_runner_(io_thread_runner),
      registry_(registry),
      routing_id_(-1),
      process_id_(process_id),
      weak_ptr_factory_(this) {}

ResourceMessageFilter::~ResourceMessageFilter() {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());
  DCHECK(is_channel_closed_);
  DCHECK(!weak_ptr_factory_.HasWeakPtrs());
}

void ResourceMessageFilter::OnFilterAdded(IPC::Channel*) {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());
  InitializeOnIOThread();
}

void ResourceMessageFilter::OnChannelClosing() {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());

  prefetch_url_loader_service_ = nullptr;
  url_loader_factory_ = nullptr;

  // Unhook us from all pending network requests so they don't get sent to a
  // deleted object.
  ResourceDispatcherHost::Get()->CancelRequestsForProcess(
      requester_info_->child_id());

  weak_ptr_factory_.InvalidateWeakPtrs();
  is_channel_closed_ = true;
}

bool ResourceMessageFilter::OnMessageReceived(const IPC::Message& message) {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());
  return false;
}

void ResourceMessageFilter::OnDestruct() const {
  // Destroy the filter on the IO thread since that's where its weak pointers
  // are being used.
  if (io_thread_task_runner_->BelongsToCurrentThread()) {
    delete this;
  } else {
    io_thread_task_runner_->DeleteSoon(FROM_HERE, this);
  }
}

base::WeakPtr<ResourceMessageFilter> ResourceMessageFilter::GetWeakPtr() {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());
  return is_channel_closed_ ? nullptr : weak_ptr_factory_.GetWeakPtr();
}

void ResourceMessageFilter::CreateLoaderAndStart(network::mojom::URLLoaderRequest request,
                                                 int32_t routing_id,
                                                 int32_t request_id,
                                                 uint32_t options,
                                                 const network::ResourceRequest& url_request,
                                                 network::mojom::URLLoaderClientPtr client,
                                                 const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ResourceMessageFilter::GetEncoderAndCreateLoader, 
      base::Unretained(this),
      base::Passed(std::move(request)),
      routing_id,
      request_id,
      options,
      url_request,
      base::Passed(std::move(client)),
      traffic_annotation));
}

void ResourceMessageFilter::GetEncoderAndCreateLoader(
  network::mojom::URLLoaderRequest request,
  int32_t routing_id,
  int32_t request_id,
  uint32_t options,
  const network::ResourceRequest& url_request,
  network::mojom::URLLoaderClientPtr client,
  const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  
  DLOG(INFO) << "ResourceMessageFilter::GetEncoderAndCreateLoader: ApplicationWindowHost::FromID process_id: " << process_id_ << " routing_id: " << routing_id_;  

  ApplicationWindowHost* awh = ApplicationWindowHost::FromID(process_id_, routing_id_);
  DCHECK(awh);
  NavigationEntry* entry = awh->delegate()->GetNavigationController()->current();
  //RouteController* controller = awh->delegate()->GetRouteController();
  RouteEntry* url_entry = entry->route();
  DCHECK(url_entry);
  HostRpcService* service = url_entry->service();
  DCHECK(service);
  std::unique_ptr<net::RpcMessageEncoder> encoder = service->BuildEncoder();
  HostNetworkContext* network_context = awh->GetNetworkContext();

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
   base::BindOnce(&ResourceMessageFilter::CreateLoaderAndStartImpl, 
    base::Unretained(this),
    base::Passed(std::move(request)),
    routing_id,
    request_id,
    options,
    url_request,
    base::Passed(std::move(client)),
    traffic_annotation,
    base::Unretained(network_context),
    base::Passed(std::move(encoder))));
   
}

void ResourceMessageFilter::CreateLoaderAndStartImpl(
    network::mojom::URLLoaderRequest request,
    int32_t routing_id,
    int32_t request_id,
    uint32_t options,
    const network::ResourceRequest& url_request,
    network::mojom::URLLoaderClientPtr client,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation,
    HostNetworkContext* network_context,
    std::unique_ptr<net::RpcMessageEncoder> encoder) {
  DLOG(INFO) << "ResourceMessageFilter::CreateLoaderAndStart";
  routing_id_ = routing_id;
  // if (g_test_factory && !g_current_filter) {
  //   g_current_filter = this;
  //   g_test_factory->CreateLoaderAndStart(std::move(request), routing_id,
  //                                        request_id, options, url_request,
  //                                        std::move(client), traffic_annotation);
  //   g_current_filter = nullptr;
  //   return;
  // }

  // TODO(kinuko): Remove this flag guard when we have more confidence, this
  // doesn't need to be paired up with SignedExchange feature.
  // if (base::FeatureList::IsEnabled(features::kSignedHTTPExchange) &&
  //     url_request.resource_type == RESOURCE_TYPE_PREFETCH &&
  //     prefetch_url_loader_service_) {
  //   prefetch_url_loader_service_->CreateLoaderAndStart(
  //       std::move(request), routing_id, request_id, options, url_request,
  //       std::move(client), traffic_annotation,
  //       base::MakeRefCounted<WeakWrapperSharedURLLoaderFactory>(
  //           url_loader_factory_.get()),
  //       base::BindRepeating(&GetFrameTreeNodeId, child_id(),
  //                           url_request.render_frame_id));
  //   return;
  // }

  if (!url_loader_factory_) {
    network::mojom::URLLoaderFactoryRequest request;
    //mojo::MakeRequest(&request);
    url_loader_factory_ = network_context->CreateRpcURLLoaderFactory(
        io_thread_task_runner_,
        registry_,
        std::move(encoder),
        routing_id_,
        process_id_,
        std::move(request));
  }

  url_loader_factory_->CreateLoaderAndStart(
      std::move(request), routing_id, request_id, options, url_request,
      std::move(client), traffic_annotation);
}

void ResourceMessageFilter::Clone(
    network::mojom::URLLoaderFactoryRequest request) {
  url_loader_factory_->Clone(std::move(request));
}

int ResourceMessageFilter::child_id() const {
  return requester_info_->child_id();
}

void ResourceMessageFilter::InitializeForTest() {
  InitializeOnIOThread();
}

void ResourceMessageFilter::SetNetworkFactoryForTesting(
    network::mojom::URLLoaderFactory* test_factory) {
  DCHECK(!HostThread::IsThreadInitialized(HostThread::IO) ||
         HostThread::CurrentlyOn(HostThread::IO));
  DCHECK(!test_factory || !g_test_factory);
  g_test_factory = test_factory;
}

ResourceMessageFilter* ResourceMessageFilter::GetCurrentForTesting() {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  return g_current_filter;
}

void ResourceMessageFilter::InitializeOnIOThread() {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());
  // The WeakPtr of the filter must be created on the IO thread. So sets the
  // WeakPtr of |requester_info_| now.
  requester_info_->set_filter(GetWeakPtr());
  //url_loader_factory_ = std::make_unique<URLLoaderFactoryImpl>(requester_info_);
  
  if (!registry_) {
    owned_url_loader_factory_ = std::make_unique<URLLoaderFactoryImpl>(requester_info_);
    url_loader_factory_ = owned_url_loader_factory_.get();
  }
  //url_loader_factory_ = std::make_unique<RpcURLLoaderFactory>(requester_info_);

  // if (base::FeatureList::IsEnabled(network::features::kOutOfBlinkCORS)) {
  //   url_loader_factory_ = std::make_unique<network::cors::CORSURLLoaderFactory>(
  //       std::move(url_loader_factory_));
  // }
}

}  // namespace host
