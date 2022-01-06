// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RPC_URL_LOADER_H_
#define MUMBA_HOST_APPLICATION_RPC_URL_LOADER_H_

#include <memory>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "net/base/load_states.h"
#include "net/http/http_raw_request_headers.h"
//#include "net/traffic_annotation/network_traffic_annotation.h"
//#include "net/url_request/url_request.h"
#include "services/network/keepalive_statistics_recorder.h"
//#include "services/network/public/mojom/network_service.mojom.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/resource_scheduler.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/upload_progress_tracker.h"
#include "core/shared/common/content_export.h"
#include "net/rpc/server/rpc_service.h"
#include "core/host/rpc/client/rpc_host.h"
#include "core/host/rpc/client/rpc_client.h"

namespace net {
class HttpResponseHeaders;
class RpcMessageEncoder;
}

namespace network {
class NetToMojoPendingBuffer;
class KeepaliveStatisticsRecorder;
struct ResourceResponse;
}

namespace host {
class RouteRegistry;
class RouteEntry;

// URL loader like, but focused on Rpc's
class CONTENT_EXPORT RpcURLLoader : public network::mojom::URLLoader,
                                    public net::URLRequest::Delegate {
public:
  using DeleteCallback = base::OnceCallback<void(network::mojom::URLLoader* url_loader)>;

  RpcURLLoader(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    net::URLRequestContext* url_request_context,
    RouteRegistry* registry,
    RouteEntry* route_entry,
    DeleteCallback delete_callback,
    network::mojom::URLLoaderRequest url_loader_request,
    int32_t options,
    const network::ResourceRequest& request,
    bool report_raw_headers,
    network::mojom::URLLoaderClientPtr url_loader_client,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    uint32_t process_id,
    uint32_t request_id);

  ~RpcURLLoader();

  // mojom::URLLoader implementation:
  void FollowRedirect() override;
  void ProceedWithResponse() override;
  void SetPriority(net::RequestPriority priority,
                   int32_t intra_priority_value) override;
  void PauseReadingBodyFromNet() override;
  void ResumeReadingBodyFromNet() override;

  // net::URLRequest::Delegate implementation:
  //void OnReceivedRedirect(net::URLRequest* url_request,
  //                        const net::RedirectInfo& redirect_info,
  //                        bool* defer_redirect) override;
  //void OnAuthRequired(net::URLRequest* request,
  //                    net::AuthChallengeInfo* info) override;
  //void OnCertificateRequested(net::URLRequest* request,
  //                            net::SSLCertRequestInfo* info) override;
  //void OnSSLCertificateError(net::URLRequest* request,
  //                           const net::SSLInfo& info,
  //                           bool fatal) override;
  void OnResponseStarted(net::URLRequest* url_request, int net_error) override;
  void OnReadCompleted(net::URLRequest* url_request, int bytes_read) override;

private:
  
  void ReadMore();
  void DidRead(int num_bytes, bool completed_synchronously);
  void NotifyCompleted(int error_code);
  void OnResponseBodyStreamConsumerClosed(MojoResult result);
  void OnResponseBodyStreamReady(MojoResult result);
  void OnConnectionError();
  void SendResponseToClient();
  void SetRawResponseHeaders(scoped_refptr<const net::HttpResponseHeaders>);
  void CompletePendingWrite();
  void DeleteSelf();
  void ResumeStart();

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  net::URLRequestContext* url_request_context_;
  RouteRegistry* route_registry_;
  RouteEntry* route_entry_;
  //net::RpcMessageEncoder* encoder_;
  //network::mojom::NetworkServiceClient* network_service_client_;
  DeleteCallback delete_callback_;

  int32_t options_;
  //int resource_type_;
  bool is_load_timing_enabled_;
  //uint32_t process_id_;
  //uint32_t render_frame_id_;
 // uint32_t request_id_;
  const bool keepalive_;
  std::unique_ptr<net::URLRequest> url_request_;
  mojo::Binding<network::mojom::URLLoader> binding_;
  //mojo::Binding<mojom::AuthChallengeResponder>
  //    auth_challenge_responder_binding_;
  network::mojom::URLLoaderClientPtr url_loader_client_;
  int64_t total_written_bytes_ = 0;

  mojo::ScopedDataPipeProducerHandle response_body_stream_;
  scoped_refptr<network::NetToMojoPendingBuffer> pending_write_;
  uint32_t pending_write_buffer_size_ = 0;
  uint32_t pending_write_buffer_offset_ = 0;
  mojo::SimpleWatcher writable_handle_watcher_;
  mojo::SimpleWatcher peer_closed_handle_watcher_;

  // Used when deferring sending the data to the client until mime sniffing is
  // finished.
  scoped_refptr<network::ResourceResponse> response_;
  mojo::ScopedDataPipeConsumerHandle consumer_handle_;

  //std::unique_ptr<network::ResourceScheduler::ScheduledResourceRequest>
  //    resource_scheduler_request_handle_;

  bool report_raw_headers_;
  net::HttpRawRequestHeaders raw_request_headers_;
  scoped_refptr<const net::HttpResponseHeaders> raw_response_headers_;

  //bool should_pause_reading_body_ = false;
  // The response body stream is open, but transferring data is paused.
  //bool paused_reading_body_ = false;

  // Whether to update |body_read_before_paused_| after the pending read is
  // completed (or when the response body stream is closed).
  //bool update_body_read_before_paused_ = false;
  // The number of bytes obtained by the reads initiated before the last
  // PauseReadingBodyFromNet() call. -1 means the request hasn't been paused.
  // The body may be read from cache or network. So even if this value is not
  // -1, we still need to check whether it is from network before reporting it
  // as BodyReadFromNetBeforePaused.
  //int64_t body_read_before_paused_ = -1;

  // This is used to compute the delta since last time received
  // encoded body size was reported to the client.
  int64_t reported_total_encoded_bytes_ = 0;

  //scoped_refptr<network::ResourceSchedulerClient> resource_scheduler_client_;

  base::WeakPtrFactory<RpcURLLoader> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcURLLoader);
};

}

#endif