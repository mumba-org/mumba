// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_IPC_URL_LOADER_H_
#define MUMBA_HOST_APPLICATION_IPC_URL_LOADER_H_

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
#include "services/network/keepalive_statistics_recorder.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/resource_scheduler.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/upload_progress_tracker.h"
#include "core/shared/common/content_export.h"
#include "core/host/route/route_request.h"

namespace net {
class HttpResponseHeaders;
class RpcMessageEncoder;
}

namespace network {
class NetToMojoPendingBuffer;
class KeepaliveStatisticsRecorder;
struct ResourceResponse;
}

namespace common {
namespace mojom {
class RouteDispatcher;
}
}

namespace host {
class RouteRegistry;
class RouteEntry;
class Domain;
class RouteDispatcherClient;

// URL loader like, but focused on ipc's
class CONTENT_EXPORT IpcURLLoader : public network::mojom::URLLoader,
                                    public RouteRequestDelegate {
public:
  using DeleteCallback = base::OnceCallback<void(network::mojom::URLLoader* url_loader)>;

  IpcURLLoader(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<base::SequencedTaskRunner> route_task_runner,
    net::URLRequestContext* url_request_context,
    Domain* domain,
    RouteRegistry* route_registry,
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

  ~IpcURLLoader();

  // mojom::URLLoader implementation:
  void FollowRedirect() override;
  void ProceedWithResponse() override;
  void SetPriority(net::RequestPriority priority,
                   int32_t intra_priority_value) override;
  void PauseReadingBodyFromNet() override;
  void ResumeReadingBodyFromNet() override;
  // RouteRequestDelegate
  void OnResponseStarted(RouteRequest* request, int net_error) override;
  void OnStreamReadDataAvailable(RouteRequest* request, int net_error) override;
  void OnReadCompleted(RouteRequest* request, int bytes_read) override;

private:
  
  void OnRead(int num_bytes);
  void ReadMore();
  void DidRead(int num_bytes, bool completed_synchronously);
  void NotifyCompleted(int error_code);
  void OnResponseBodyStreamReady(MojoResult result);
  void OnResponseBodyStreamConsumerClosed(MojoResult result);
  void OnConnectionError();
  void SendResponseToClient();
  void SetRawResponseHeaders(scoped_refptr<const net::HttpResponseHeaders>);
  void CompletePendingWrite();
  void DeleteSelf();
  void ResumeStart();

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  net::URLRequestContext* url_request_context_;
  Domain* domain_;
  std::unique_ptr<RouteRequest> route_request_;
  RouteRegistry* route_registry_;
  RouteEntry* route_entry_;
  DeleteCallback delete_callback_;

  int32_t options_;
  bool is_load_timing_enabled_;
  const bool keepalive_;
  mojo::Binding<network::mojom::URLLoader> binding_;
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

  bool report_raw_headers_;
  net::HttpRawRequestHeaders raw_request_headers_;
  scoped_refptr<const net::HttpResponseHeaders> raw_response_headers_;

  GURL last_url_;

  // This is used to compute the delta since last time received
  // encoded body size was reported to the client.
  int64_t reported_total_encoded_bytes_ = 0;

  base::WeakPtrFactory<IpcURLLoader> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(IpcURLLoader);
};

}

#endif