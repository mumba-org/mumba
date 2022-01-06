// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHARED_DOMAIN_ROUTE_ROUTE_DISPATCHER_H_
#define MUMBA_SHARED_DOMAIN_ROUTE_ROUTE_DISPATCHER_H_

#include <memory>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "net/base/load_states.h"
#include "net/http/http_raw_request_headers.h"
#include "services/network/keepalive_statistics_recorder.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/resource_scheduler.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/upload_progress_tracker.h"
#include "services/network/public/cpp/net_adapters.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "core/shared/common/content_export.h"

namespace net {
class HttpResponseHeaders;
class RpcMessageEncoder;
}

namespace network {
class NetToMojoPendingBuffer;
class KeepaliveStatisticsRecorder;
struct ResourceResponse;
}

namespace domain {
class DomainMainThread;

class CONTENT_EXPORT RouteRequest {
public:
  class CONTENT_EXPORT Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnResponseStarted(RouteRequest* request, int net_error) = 0;
    virtual void OnReadCompleted(RouteRequest* request, int bytes_read) = 0;
  };
  virtual ~RouteRequest() {}

  virtual int id() = 0;
  virtual int status() = 0;
  virtual const GURL& url() = 0;
  virtual const std::string& method() = 0;
  virtual bool is_completed() const = 0;
  virtual void GetMimeType(std::string* mime_type) = 0;
  virtual void GetCharset(std::string* charset) = 0;
  virtual base::TimeTicks GetCreationTime() = 0;
  virtual int64_t GetTotalReceivedBytes() = 0;
  virtual int64_t GetRawBodyBytes() = 0;
  virtual void GetLoadTimingInfo(net::LoadTimingInfo* load_timing_info) = 0;
  virtual int64_t GetExpectedContentSize() = 0;
  virtual net::HttpResponseHeaders* GetResponseHeaders() = 0;
  virtual const net::HttpResponseInfo& GetResponseInfo() = 0;
  virtual void Start(base::OnceCallback<void(int)>) = 0;
  virtual void SetExtraRequestHeaders(const net::HttpRequestHeaders& headers) = 0;
  virtual void FollowDeferredRedirect() = 0;
  virtual bool Read(net::IOBuffer* buf, int max_bytes, int* bytes_read) = 0;
  virtual int CancelWithError(int error) = 0;
  virtual void Complete(int code) = 0;
};

struct RouteResponse {

  RouteResponse(
    const network::ResourceRequest& request,
    bool report_raw_headers);

  bool is_load_timing_enabled;
  const bool keepalive;
  int64_t total_written_bytes = 0;

  mojo::ScopedDataPipeProducerHandle body_sender;
  mojo::ScopedDataPipeConsumerHandle body_receiver;
  scoped_refptr<network::NetToMojoPendingBuffer> pending_write;
  uint32_t pending_write_buffer_size = 0;
  uint32_t pending_write_buffer_offset = 0;
  mojo::SimpleWatcher writable_handle_watcher;
  mojo::SimpleWatcher writable_handle_closed_watcher;
  mojo::SimpleWatcher readable_handle_watcher;
  mojo::SimpleWatcher readable_handle_closed_watcher;

  // Used when deferring sending the data to the client until mime sniffing is
  // finished.
  scoped_refptr<network::ResourceResponse> response;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;

  bool report_raw_headers;
  net::HttpRawRequestHeaders raw_request_headers;
  scoped_refptr<const net::HttpResponseHeaders> raw_response_headers;

  // This is used to compute the delta since last time received
  // encoded body size was reported to the client.
  int64_t reported_total_encoded_bytes = 0;
};

class CONTENT_EXPORT RouteDispatcher : public common::mojom::RouteDispatcher,
                                       public RouteRequest::Delegate {
public:
  class CONTENT_EXPORT Delegate {
  public:
    virtual ~Delegate() {}
    virtual std::unique_ptr<RouteRequest> CreateRequest(RouteDispatcher* dispatcher, const std::string& url, int request_id) = 0;
    // let the delegate knows that the handler completed
    // it might destroy the handler once its done
    virtual void OnComplete(RouteDispatcher* dispatcher, int request_id, network::URLLoaderCompletionStatus status) = 0;
    // control management methods
    virtual void LookupRoute(const std::string& query, LookupRouteCallback callback) = 0;
    virtual void LookupRouteByPath(const std::string& path, LookupRouteByPathCallback callback) = 0;
    virtual void LookupRouteByUrl(const GURL& url, LookupRouteByUrlCallback callback) = 0;
    virtual void LookupRouteByUUID(const std::string& uuid, LookupRouteByUUIDCallback callback) = 0;
    virtual void GetRouteHeader(const std::string& url, common::mojom::RouteDispatcher::GetRouteHeaderCallback callback) = 0;
    virtual void GetRouteCount(GetRouteCountCallback callback) = 0;
    virtual void Subscribe(common::mojom::RouteSubscriberPtr subscriber, SubscribeCallback callback) = 0;
    virtual void Unsubscribe(int32_t subscriber_id) = 0;
  };
  RouteDispatcher();
  ~RouteDispatcher();

  Delegate* delegate() const {
    return delegate_;
  }

  void set_delegate(Delegate* delegate) {
    delegate_ = delegate;
  }

  void Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  
  //void Bind(common::mojom::RouteDispatcherRequest route_dispatcher_request);
  void Bind(common::mojom::RouteDispatcherAssociatedRequest route_dispatcher_request);

  // control/management methods
  void LookupRoute(const std::string& query, LookupRouteCallback callback);
  void LookupRouteByPath(const std::string& path, LookupRouteByPathCallback callback);
  void LookupRouteByUrl(const GURL& url, LookupRouteByUrlCallback callback);
  void LookupRouteByUUID(const std::string& uuid, LookupRouteByUUIDCallback callback);
  void GetRouteHeader(const std::string& url, GetRouteHeaderCallback callback);
  void GetRouteCount(GetRouteCountCallback callback);
  void Subscribe(common::mojom::RouteSubscriberPtr subscriber, SubscribeCallback callback);
  void Unsubscribe(int32_t subscriber_id);

  // common::mojom::RouteDispatcher implementation:
  void StartRequest(int request_id, const std::string& url, mojo::ScopedDataPipeConsumerHandle receive_handle, mojo::ScopedDataPipeProducerHandle send_handle) override;
  void FollowRedirect(int request_id) override;
  void ProceedWithResponse(int request_id) override;
  void SetPriority(int request_id,
                   net::RequestPriority priority,
                   int32_t intra_priority_value) override;
  void PauseReadingBodyFromNet(int request_id) override;
  void ResumeReadingBodyFromNet(int request_id) override;
  
  void OnResponseStarted(RouteRequest* request, int net_error) override;
  void OnReadCompleted(RouteRequest* request, int bytes_read) override;

private:
  friend class DomainMainThread;

  void OnRequestStarted(RouteRequest* request, int net_error);

  void ReadMore(int request_id);
  void DidRead(int request_id, int num_bytes, bool completed_synchronously);
  void NotifyCompleted(int request_id, int error_code);
  void OnResponseBodySenderStreamWritable(int request_id, MojoResult result);
  void OnResponseBodyReceiverStreamReadable(int request_id, MojoResult result);
  void OnResponseBodySenderStreamClosed(int request_id, MojoResult result);
  void OnResponseBodyReceiverStreamClosed(int request_id, MojoResult result);
  void SendResponseToClient(int request_id);
  void SetRawResponseHeaders(int request_id, scoped_refptr<const net::HttpResponseHeaders>);
  void CompletePendingWrite(int request_id);
  void ResumeStart(int request_id);

  void StartOnImplThread(RouteRequest* request);
  void ReadOnImplThread(RouteRequest* request, RouteResponse* response, scoped_refptr<network::NetToMojoIOBuffer> buf);

  void OnConnectionError();

  RouteResponse* GetResponse(int id) {
    base::AutoLock lock(responses_lock_);
    auto it = responses_.find(id);
    if (it == responses_.end()) {
      return nullptr;
    }
    return it->second.get();
  }

  RouteRequest* GetRequest(int id) {
    base::AutoLock lock(requests_lock_);
    auto it = requests_.find(id);
    if (it == requests_.end()) {
      return nullptr;
    }
    return it->second.get();
  }

  void DropRequest(int id) {
    base::AutoLock lock(requests_lock_);
    auto it = requests_.find(id);
    if (it != requests_.end()) {
      requests_.erase(it);
    }
  }

  void DropResponse(int id) {
    base::AutoLock lock(responses_lock_);
    auto it = responses_.find(id);
    if (it != responses_.end()) {
      responses_.erase(it);
    }
  }

  void DropRequestAndResponse(int id) {
    DropResponse(id);
    DropRequest(id);
  }

  Delegate* delegate_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SequencedTaskRunner> impl_task_runner_;
  
  //mojo::Binding<common::mojom::RouteDispatcher> binding_;
  mojo::AssociatedBinding<common::mojom::RouteDispatcher> binding_;
  //common::mojom::RouteDispatcherClientPtr route_dispatcher_client_;
  common::mojom::RouteDispatcherClientAssociatedPtr route_dispatcher_client_;
  std::unordered_map<int, std::unique_ptr<RouteRequest>> requests_;
  std::unordered_map<int, std::unique_ptr<RouteResponse>> responses_;
  std::unordered_map<int, std::unique_ptr<mojo::DataPipe>> response_bodies_;

  int next_request_id_;

  base::Lock requests_lock_;
  base::Lock responses_lock_;

  base::WeakPtrFactory<RouteDispatcher> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(RouteDispatcher);
};

}

#endif