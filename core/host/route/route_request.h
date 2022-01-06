// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REQUEST_H_
#define MUMBA_CORE_HOST_ROUTE_REQUEST_H_

#include <memory>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "net/base/load_states.h"
#include "net/http/http_response_info.h"
#include "net/http/http_raw_request_headers.h"
#include "services/network/keepalive_statistics_recorder.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/resource_scheduler.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/upload_progress_tracker.h"
#include "services/network/public/cpp/net_adapters.h"
#include "services/network/public/cpp/resource_response_info.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "core/host/route/route_request_delegate.h"
#include "core/host/route/route_request_peer.h"

namespace net {
class HttpResponseHeaders;
}

namespace network {
class KeepaliveStatisticsRecorder;
struct ResourceResponse;
}

namespace host {
class RouteDispatcherClient;
class IpcRouteRequestPeer;

class RouteRequest : public RouteRequestPeer::Delegate {
public:
  enum State {
    STATE_NONE = 0,
    STATE_CREATE_STREAM = 1,
    STATE_SEND_REQUEST = 2,
    STATE_REPLY_RECEIVED = 3,
    STATE_CLOSE_STREAM = 4,
  };
  RouteRequest(int id,
               base::WeakPtr<RouteRequestDelegate> delegate, 
               RouteDispatcherClient* route_dispatcher_client, 
               const GURL& url, 
               scoped_refptr<base::SequencedTaskRunner> route_task_runner);
               
  ~RouteRequest() override;

  int id() const {
    return id_;
  }

  const GURL& url() const {
    return url_;
  }

  // RouteRequestDelegate* delegate() const {
  //   return delegate_;
  // }

  IpcRouteRequestPeer* peer() const {
    return peer_.get();
  }

  RouteDispatcherClient* route_dispatcher_client() const {
    return route_dispatcher_client_;
  }

  int status() const {
    return status_;
  }

  State state() const {
    return state_;
  }

  int64_t GetTotalReceivedBytes() const {
    return total_readed_bytes_;
  }
  int64_t GetTotalSentBytes() const {
    return total_sent_bytes_; 
  }
  int64_t GetRawBodyBytes() const {
    return content_lenght_;
  }

  const network::ResourceResponseInfo& response_info() const { 
    return response_info_; 
  }

  base::TimeTicks creation_time() const { 
    return creation_time_; 
  }

  const base::Time& request_time() const {
    return response_info_.request_time;
  }

  const base::Time& response_time() const {
    return response_info_.response_time;
  }

  // Returns true if the URLRequest was delivered through a proxy.
  bool was_fetched_via_proxy() const {
    return response_info_.was_fetched_via_proxy;
  }

  net::HttpResponseHeaders* response_headers() const;

  // Returns the expected content size if available
  int64_t GetExpectedContentSize() const {
    return expected_content_size_;
  }

  void GetLoadTimingInfo(net::LoadTimingInfo* load_timing_info) const;
  void GetMimeType(std::string* mime_type) const;
  void GetCharset(std::string* charset) const;

  void Start();
  void Read(net::IOBuffer* buf, int max_bytes, base::OnceCallback<void(int)> callback);
  void CancelWithError(int error_code);

  // RouteRequestPeer::Delegate
  void OnRequestStarted(int request_id) override;
  void OnUploadProgress(int request, uint64_t position, uint64_t size) override;
  bool OnReceivedRedirect(int request, const net::RedirectInfo& redirect_info, 
                        const network::ResourceResponseInfo& info,
                        scoped_refptr<base::SingleThreadTaskRunner> task_runner) override;
  void OnReceivedResponse(int request, const network::ResourceResponseHead& response_head) override;
  void OnStartLoadingResponseBody(int request, mojo::ScopedDataPipeConsumerHandle body) override;
  void OnDownloadedData(int request, int len, int encoded_data_length) override;
  void OnReceivedData(int request, std::unique_ptr<RouteRequestPeer::ReceivedData> data) override;
  void OnTransferSizeUpdated(int request, int transfer_size_diff) override;
  void OnReceivedCachedMetadata(int request, const std::vector<uint8_t>& data, int len) override;
  void OnCompletedRequest(int request, const network::URLLoaderCompletionStatus& status) override;

private:

  void OnStreamAvailable(mojo::ScopedDataPipeConsumerHandle send_handle, 
                         mojo::ScopedDataPipeProducerHandle receive_handle);
  void OnStreamReadDataAvailable(int code);
  void CloseStream();
  void OnNetworkReadCompleted(int status);
  void OnStreamSendEvent(MojoResult result);
  void OnStreamSendClose(MojoResult result);
  void OnStreamReceiveEvent(MojoResult result);
  void OnStreamReceiveClose(MojoResult result);
  void ReadMore();
  void CompletePendingRead();
  void ShutdownReceive();
  void ShutdownSend();

  void StartImpl();
  void StartRequestOnMainThread(mojo::ScopedDataPipeConsumerHandle send_handle, 
                                mojo::ScopedDataPipeProducerHandle receive_handle);
  void ReadImpl(net::IOBuffer* buf, int max_bytes, base::OnceCallback<void(int)> callback);

  int id_;
  base::WeakPtr<RouteRequestDelegate> delegate_;
  RouteDispatcherClient* route_dispatcher_client_;
  common::mojom::RouteDispatcher* route_dispatcher_;
  std::unique_ptr<IpcRouteRequestPeer> peer_;
  State state_;
  int status_;
  GURL url_;
  int64_t total_sent_bytes_;
  int64_t total_readed_bytes_;
  int64_t content_lenght_;
  int64_t expected_content_size_;
  bool is_pending_read_;
  base::TimeTicks creation_time_;
  //net::HttpResponseInfo response_info_;
  network::ResourceResponseInfo response_info_;
  mojo::ScopedDataPipeProducerHandle send_handle_;
  mojo::ScopedDataPipeConsumerHandle receive_handle_;
  scoped_refptr<network::MojoToNetPendingBuffer> pending_receive_buffer_;
  scoped_refptr<network::NetToMojoPendingBuffer> pending_send_buffer_;
  uint32_t pending_read_buffer_size_ = 0;
  uint32_t pending_read_buffer_offset_ = 0;
  mojo::SimpleWatcher send_handle_watcher_;
  mojo::SimpleWatcher send_handle_closed_watcher_;
  mojo::SimpleWatcher receive_handle_watcher_;
  mojo::SimpleWatcher receive_handle_closed_watcher_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SequencedTaskRunner> impl_task_runner_;
  base::WeakPtrFactory<RouteRequest> main_weak_ptr_;
  base::WeakPtrFactory<RouteRequest> impl_weak_ptr_;

  DISALLOW_COPY_AND_ASSIGN(RouteRequest);
};

}

#endif