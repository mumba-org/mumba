// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/resource_dispatcher_host.h"

#include "core/host/application/resource_dispatcher_host_delegate.h"
#include "services/network/loader_util.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/request_context_frame_type.mojom.h"
#include "services/network/resource_scheduler.h"
//#include "services/network/throttling/scoped_throttling_token.h"
#include "services/network/url_loader_factory.h"

namespace host {

static ResourceDispatcherHost* g_resource_dispatcher_host;

// static 
ResourceDispatcherHost* ResourceDispatcherHost::Get() {
  return g_resource_dispatcher_host;
}

ResourceDispatcherHost::ResourceDispatcherHost(const scoped_refptr<base::SingleThreadTaskRunner>& io_thread_runner):
 request_id_(-1),
 io_thread_task_runner_(io_thread_runner) {
  g_resource_dispatcher_host = this;
}

ResourceDispatcherHost::~ResourceDispatcherHost() {
  g_resource_dispatcher_host = nullptr;
}

void ResourceDispatcherHost::SetDelegate(ResourceDispatcherHostDelegate* delegate) {
  delegate_ = delegate;
}

void ResourceDispatcherHost::SetAllowCrossOriginAuthPrompt(bool value) {

}

void ResourceDispatcherHost::RegisterInterceptor(
  const std::string& http_header,
  const std::string& starts_with,
  const InterceptorCallback& interceptor) {

}

void ResourceDispatcherHost::ReprioritizeRequest(
  net::URLRequest* request,
  net::RequestPriority priority) {

}

void ResourceDispatcherHost::Shutdown() {

}

void ResourceDispatcherHost::CancelRequestsForContext(
    ResourceContext* context) {
}

// The object died, so cancel and detach all requests associated with it except
// for downloads and detachable resources, which belong to the browser process
// even if initiated via a renderer.
void ResourceDispatcherHost::CancelRequestsForProcess(int child_id) {
  // CancelRequestsForRoute(
  //     GlobalFrameRoutingId(child_id, MSG_ROUTING_NONE /* cancel all */));
  // const auto& map = keepalive_statistics_recorder_.per_process_records();
  // if (map.find(child_id) != map.end())
  //   keepalive_statistics_recorder_.Unregister(child_id);
  // registered_temp_files_.erase(child_id);
}

void ResourceDispatcherHost::CancelRequestsForRoute(
    const GlobalFrameRoutingId& global_routing_id) {
  // Since pending_requests_ is a map, we first build up a list of all of the
  // matching requests to be cancelled, and then we cancel them.  Since there
  // may be more than one request to cancel, we cannot simply hold onto the map
  // iterators found in the first loop.

  // Find the global ID of all matching elements.
  // int child_id = global_routing_id.child_id;
  // int route_id = global_routing_id.frame_routing_id;
  // bool cancel_all_routes = (route_id == MSG_ROUTING_NONE);

  // bool any_requests_transferring = false;
  // std::vector<GlobalRequestID> matching_requests;
  // for (const auto& loader : pending_loaders_) {
  //   if (loader.first.child_id != child_id)
  //     continue;

  //   ResourceRequestInfo* info = loader.second->GetRequestInfo();

  //   GlobalRequestID id(child_id, loader.first.request_id);
  //   DCHECK(id == loader.first);
  //   // Don't cancel navigations that are expected to live beyond this process.
  //   if (IsTransferredNavigation(id))
  //     any_requests_transferring = true;
  //   if (cancel_all_routes || route_id == info->GetRenderFrameID()) {
  //     if (info->keepalive() && !cancel_all_routes) {
  //       // If the keepalive flag is set, that request will outlive the frame
  //       // deliberately, so we don't cancel it here.
  //     } else if (info->detachable_handler()) {
  //       info->detachable_handler()->Detach();
  //     } else if (!info->IsDownload() && !info->is_stream() &&
  //                !IsTransferredNavigation(id)) {
  //       matching_requests.push_back(id);
  //     }
  //   }
  // }

  // // Remove matches.
  // for (size_t i = 0; i < matching_requests.size(); ++i) {
  //   LoaderMap::iterator iter = pending_loaders_.find(matching_requests[i]);
  //   // Although every matching request was in pending_requests_ when we built
  //   // matching_requests, it is normal for a matching request to be not found
  //   // in pending_requests_ after we have removed some matching requests from
  //   // pending_requests_.  For example, deleting a net::URLRequest that has
  //   // exclusive (write) access to an HTTP cache entry may unblock another
  //   // net::URLRequest that needs exclusive access to the same cache entry, and
  //   // that net::URLRequest may complete and remove itself from
  //   // pending_requests_. So we need to check that iter is not equal to
  //   // pending_requests_.end().
  //   if (iter != pending_loaders_.end())
  //     RemovePendingLoader(iter);
  // }

  // // Don't clear the blocked loaders or offline policy maps if any of the
  // // requests in route_id are being transferred to a new process, since those
  // // maps will be updated with the new route_id after the transfer.  Otherwise
  // // we will lose track of this info when the old route goes away, before the
  // // new one is created.
  // if (any_requests_transferring)
  //   return;

  // // Now deal with blocked requests if any.
  // if (!cancel_all_routes) {
  //   if (blocked_loaders_map_.find(global_routing_id) !=
  //       blocked_loaders_map_.end()) {
  //     CancelBlockedRequestsForRoute(global_routing_id);
  //   }
  // } else {
  //   // We have to do all render frames for the process |child_id|.
  //   // Note that we have to do this in 2 passes as we cannot call
  //   // CancelBlockedRequestsForRoute while iterating over
  //   // blocked_loaders_map_, as blocking requests modifies the map.
  //   std::set<GlobalFrameRoutingId> routing_ids;
  //   for (const auto& blocked_loaders : blocked_loaders_map_) {
  //     if (blocked_loaders.first.child_id == child_id)
  //       routing_ids.insert(blocked_loaders.first);
  //   }
  //   for (const GlobalFrameRoutingId& frame_route_id : routing_ids) {
  //     CancelBlockedRequestsForRoute(frame_route_id);
  //   }
  // }
}

void ResourceDispatcherHost::CancelBlockedRequestsForRoute(
    const GlobalFrameRoutingId& global_routing_id) {
  //ProcessBlockedRequestsForRoute(global_routing_id, true);
}

void ResourceDispatcherHost::ProcessBlockedRequestsForRoute(
    const GlobalFrameRoutingId& global_routing_id,
    bool cancel_requests) {
  // BlockedLoadersMap::iterator iter =
  //     blocked_loaders_map_.find(global_routing_id);
  // if (iter == blocked_loaders_map_.end()) {
  //   // It's possible to reach here if the renderer crashed while an interstitial
  //   // page was showing.
  //   return;
  // }

  // BlockedLoadersList* loaders = iter->second.get();
  // std::unique_ptr<BlockedLoadersList> deleter(std::move(iter->second));

  // // Removing the vector from the map unblocks any subsequent requests.
  // blocked_loaders_map_.erase(iter);

  // for (std::unique_ptr<ResourceLoader>& loader : *loaders) {
  //   ResourceRequestInfo* info = loader->GetRequestInfo();
  //   if (cancel_requests) {
  //     IncrementOutstandingRequestsMemory(-1, *info);
  //   } else {
  //     StartLoading(info, std::move(loader));
  //   }
  // }
}

ResourceDispatcherHost::OustandingRequestsStats
ResourceDispatcherHost::IncrementOutstandingRequestsMemory(
    int count,
    const ResourceRequestInfo& info) {
  // DCHECK_EQ(1, abs(count));

  // // Retrieve the previous value (defaulting to 0 if not found).
  // OustandingRequestsStats stats = GetOutstandingRequestsStats(info);

  // // Insert/update the total; delete entries when their count reaches 0.
  // stats.memory_cost += count * info.memory_cost();
  // DCHECK_GE(stats.memory_cost, 0);
  // UpdateOutstandingRequestsStats(info, stats);

  // return stats;
  return ResourceDispatcherHost::OustandingRequestsStats();
}

void ResourceDispatcherHost::StartLoading(
    ResourceRequestInfo* info,
    std::unique_ptr<ResourceLoader> loader) {
  // ResourceLoader* loader_ptr = loader.get();
  // DCHECK(pending_loaders_[info->GetGlobalRequestID()] == nullptr);
  // pending_loaders_[info->GetGlobalRequestID()] = std::move(loader);
  // if (info->keepalive())
  //   keepalive_statistics_recorder_.OnLoadStarted(info->GetChildID());

  // loader_ptr->StartRequest();
}

int ResourceDispatcherHost::MakeRequestID() {
  DCHECK(io_thread_task_runner_->BelongsToCurrentThread());
  return --request_id_;
}

// Called when loading a request with mojo.
void ResourceDispatcherHost::OnRequestResourceWithMojo(
      ResourceRequesterInfo* requester_info,
      int32_t routing_id,
      int32_t request_id,
      uint32_t options,
      const network::ResourceRequest& request,
      network::mojom::URLLoaderRequest mojo_request,
      network::mojom::URLLoaderClientPtr url_loader_client,
      const net::NetworkTrafficAnnotationTag& traffic_annotation) {
  DLOG(ERROR) << "ResourceDispatcherHost::OnRequestResourceWithMojo: NOT IMPLEMENTED. resquest will not go forward";
  DCHECK(false);
  bool is_sync_load = options & network::mojom::kURLLoadOptionSynchronous;
  OnRequestResourceInternal(requester_info, routing_id, request_id,
                            is_sync_load, request, options,
                            std::move(mojo_request),
                            std::move(url_loader_client), traffic_annotation);
}

void ResourceDispatcherHost::OnRequestResourceInternal(
    ResourceRequesterInfo* requester_info,
    int routing_id,
    int request_id,
    bool is_sync_load,
    const network::ResourceRequest& request_data,
    uint32_t url_loader_options,
    network::mojom::URLLoaderRequest mojo_request,
    network::mojom::URLLoaderClientPtr url_loader_client,
    const net::NetworkTrafficAnnotationTag& traffic_annotation) {
  // DCHECK(requester_info->IsRenderer() ||
  //        requester_info->IsNavigationPreload() ||
  //        requester_info->IsCertificateFetcherForSignedExchange());
  // BeginRequest(requester_info, request_id, request_data, is_sync_load,
  //              routing_id, url_loader_options, std::move(mojo_request),
  //              std::move(url_loader_client), traffic_annotation);
}

}