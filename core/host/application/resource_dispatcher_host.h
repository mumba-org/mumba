// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RESOURCE_DISPATCHER_HOST_H_
#define MUMBA_HOST_APPLICATION_RESOURCE_DISPATCHER_HOST_H_

#include <string>

#include "base/macros.h"
#include "base/callback_forward.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "core/host/application/resource_context.h"
#include "core/host/application/resource_request_info.h"
#include "core/host/global_routing_id.h"
#include "net/base/request_priority.h"
#include "net/base/load_states.h"
#include "services/network/public/mojom/url_loader.mojom.h"

namespace net {
class HttpRequestHeaders;
class URLRequest;
class URLRequestContextGetter;
}

namespace network {
class ResourceScheduler;
}  // namespace network

namespace host {
class ResourceContext;
class ResourceDispatcherHostDelegate;
class ApplicationContents;
class ResourceRequesterInfo;

// FIXME
struct ResourceLoader {};

// This value is returned by header interceptors below, to determine if a
// request should proceed based on the values of HTTP headers.
enum class HeaderInterceptorResult {
  // Allow the request to proceed with the given headers.
  CONTINUE,

  // Force the request to fail, since the headers were not supported values.
  FAIL,

  // Force the request to fail and kill the renderer process, since it attempted
  // to use an illegal header value that could pose a security risk.
  KILL,
};

// This callback is invoked when the interceptor finishes processing the
// header.
// Parameter 1 indicates whether to continue the request, fail it, or kill the
// renderer process (and fail it).
typedef base::Callback<void(HeaderInterceptorResult)> OnHeaderProcessedCallback;

// This callback is registered by interceptors who are interested in being
// notified of certain HTTP headers in outgoing requests. For e.g. Origin.
// Parameter 1 contains the HTTP header.
// Parameter 2 contains its value.
// Parameter 3 contains the child process id.
// Parameter 4 contains the current ResourceContext.
// Parameter 5 contains the callback which needs to be invoked once the
// interceptor finishes its processing.
typedef base::Callback<void(const std::string&,
                            const std::string&,
                            int,
                            ResourceContext*,
                            OnHeaderProcessedCallback)>
    InterceptorCallback;

class CONTENT_EXPORT ResourceDispatcherHost {
public:
  static ResourceDispatcherHost* Get();

  ResourceDispatcherHost(const scoped_refptr<base::SingleThreadTaskRunner>& io_thread_runner);
  ~ResourceDispatcherHost();

  // This does not take ownership of the delegate. It is expected that the
  // delegate have a longer lifetime than the ResourceDispatcherHost.
  void SetDelegate(ResourceDispatcherHostDelegate* delegate);

  // Controls whether third-party sub-content can pop-up HTTP basic auth
  // dialog boxes.
  void SetAllowCrossOriginAuthPrompt(bool value);

  // Registers the |interceptor| for the |http_header| passed in.
  // The |starts_with| parameter is used to match the prefix of the
  // |http_header| in the response and the interceptor will be invoked if there
  // is a match. If the |starts_with| parameter is empty, the interceptor will
  // be invoked for every occurrence of the |http_header|.
  // Currently only HTTP header based interceptors are supported.
  // At the moment we only support one interceptor per |http_header|.
  void RegisterInterceptor(const std::string& http_header,
                           const std::string& starts_with,
                           const InterceptorCallback& interceptor);

  // Updates the priority for |request|. Modifies request->priority(), and may
  // start the request loading if it wasn't already started.
  void ReprioritizeRequest(net::URLRequest* request,
                           net::RequestPriority priority);

  // Puts the resource dispatcher host in an inactive state (unable to begin
  // new requests).  Cancels all pending requests.
  void Shutdown();

  void CancelRequestsForContext(ResourceContext* context);
  void CancelRequestsForProcess(int child_id);

  // Called when loading a request with mojo.
  void OnRequestResourceWithMojo(
      ResourceRequesterInfo* requester_info,
      int32_t routing_id,
      int32_t request_id,
      uint32_t options,
      const network::ResourceRequest& request,
      network::mojom::URLLoaderRequest mojo_request,
      network::mojom::URLLoaderClientPtr url_loader_client,
      const net::NetworkTrafficAnnotationTag& traffic_annotation);

  // Creates a new request ID for browser initiated requests. See the comments
  // of |request_id_| for the details. Must be called on the IO thread.
  int MakeRequestID();

private:
  struct OustandingRequestsStats {
    int memory_cost;
    int num_requests;
  };
   // Information about status of a ResourceLoader.
  struct CONTENT_EXPORT LoadInfo {
    LoadInfo();
    LoadInfo(const LoadInfo& other);
    ~LoadInfo();

    ResourceRequestInfo::ApplicationContentsGetter app_contents_getter;

    // Comes directly from GURL::host() to avoid copying an entire GURL between
    // threads.
    std::string host;

    net::LoadStateWithParam load_state;
    uint64_t upload_position;
    uint64_t upload_size;
  };

  // Map from ApplicationContents* to the "most interesting" LoadState.
  typedef std::map<ApplicationContents*, LoadInfo> LoadInfoMap;
  typedef std::vector<LoadInfo> LoadInfoList;

  
  using LoaderMap = std::map<GlobalRequestID, std::unique_ptr<ResourceLoader>>;


  void StartLoading(ResourceRequestInfo* info,
                    std::unique_ptr<ResourceLoader> loader);
  
  // Called every time an outstanding request is created or deleted. |count|
  // indicates whether the request is new or deleted. |count| must be 1 or -1.
  OustandingRequestsStats IncrementOutstandingRequestsMemory(
      int count,
      const ResourceRequestInfo& info);
  // Force cancels any pending requests for the given route id.  This method
  // acts like CancelRequestsForProcess when the |route_id| member of
  // |routing_id| is MSG_ROUTING_NONE.
  void CancelRequestsForRoute(const GlobalFrameRoutingId& global_routing_id);
  // Cancels any blocked request for the specified route id.
  void CancelBlockedRequestsForRoute(
      const GlobalFrameRoutingId& global_routing_id);

  void ProcessBlockedRequestsForRoute(
    const GlobalFrameRoutingId& global_routing_id,
    bool cancel_requests);

  void OnRequestResourceInternal(
    ResourceRequesterInfo* requester_info,
    int routing_id,
    int request_id,
    bool is_sync_load,
    const network::ResourceRequest& request_data,
    uint32_t url_loader_options,
    network::mojom::URLLoaderRequest mojo_request,
    network::mojom::URLLoaderClientPtr url_loader_client,
    const net::NetworkTrafficAnnotationTag& traffic_annotation);

  LoaderMap pending_loaders_;

  using BlockedLoadersList = std::vector<std::unique_ptr<ResourceLoader>>;
  using BlockedLoadersMap =
      std::map<GlobalFrameRoutingId, std::unique_ptr<BlockedLoadersList>>;
  BlockedLoadersMap blocked_loaders_map_;

  ResourceDispatcherHostDelegate* delegate_;
  // Request ID for browser initiated requests. request_ids generated by
  // child processes are counted up from 0, while browser created requests
  // start at -2 and go down from there. (We need to start at -2 because -1 is
  // used as a special value all over the resource_dispatcher_host for
  // uninitialized variables.) This way, we no longer have the unlikely (but
  // observed in the real world!) event where we have two requests with the same
  // request_id_.
  int request_id_;
  // Task runner for the IO thead.
  scoped_refptr<base::SingleThreadTaskRunner> io_thread_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(ResourceDispatcherHost);
};

}

#endif