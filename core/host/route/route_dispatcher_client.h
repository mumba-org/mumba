// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ROUTE_ROUTE_DISPATCHER_CLIENT_H_
#define MUMBA_HOST_ROUTE_ROUTE_DISPATCHER_CLIENT_H_

#include <stdint.h>
#include <vector>
#include "base/callback_forward.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "core/host/route/route_response_body_consumer.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace net {
struct RedirectInfo;
}  // namespace net

namespace network {
struct ResourceResponseHead;
struct URLLoaderCompletionStatus;
}  // namespace network

namespace host {
class RouteRequestPeer;

struct RouteRequestInfo {
  class DeferredMessage;
  class DeferredOnReceiveResponse;
  class DeferredOnReceiveRedirect;
  class DeferredOnDataDownloaded;
  class DeferredOnUploadProgress;
  class DeferredOnReceiveCachedMetadata;
  class DeferredOnComplete;

  RouteRequestInfo(int request_id, base::WeakPtr<RouteRequestPeer> peer);
  ~RouteRequestInfo();

  scoped_refptr<RouteResponseBodyConsumer> body_consumer;
  network::mojom::DownloadedTempFilePtr downloaded_file;
  std::vector<std::unique_ptr<DeferredMessage>> deferred_messages;
  int request_id = -1;
  bool started = false;
  bool has_received_response = false;
  bool has_received_complete = false;
  bool is_deferred = false;
  int32_t accumulated_transfer_size_diff_during_deferred = 0;
  base::WeakPtr<RouteRequestPeer> peer;
};

class CONTENT_EXPORT RouteDispatcherClient final
    : public common::mojom::RouteDispatcherClient {
 public:
  RouteDispatcherClient(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  ~RouteDispatcherClient() override;

  void BindPeer(base::WeakPtr<RouteRequestPeer> peer);

  void OnRequestCreated(int request_id);

  void SetDefersLoading(int request_id);
  void UnsetDefersLoading(int request_id);
  void FlushDeferredMessages(int request_id);

  common::mojom::RouteDispatcher* route_dispatcher() const {
    return route_dispatcher_.get();
  }

  //void Bind(common::mojom::RouteDispatcherClientRequest route_dispatcher_client_request);
  void Bind(common::mojom::RouteDispatcherClientAssociatedRequest route_dispatcher_client_request);

  // common::mojom::RouteDispatcherClient
  void OnRequestStarted(int request_id) override;
  void OnReceiveResponse(
      int request_id,
      const network::ResourceResponseHead& response_head,
      network::mojom::DownloadedTempFilePtr downloaded_file) override;
  void OnReceiveRedirect(
      int request_id,
      const net::RedirectInfo& redirect_info,
      const network::ResourceResponseHead& response_head) override;
  void OnDataDownloaded(int request_id, int64_t data_len, int64_t encoded_data_len) override;
  void OnUploadProgress(int request_id, 
                        int64_t current_position,
                        int64_t total_size,
                        OnUploadProgressCallback ack_callback) override;
  void OnReceiveCachedMetadata(int request_id, const std::vector<uint8_t>& data) override;
  void OnTransferSizeUpdated(int request_id, int32_t transfer_size_diff) override;
  void OnStartLoadingResponseBody(int request_id, mojo::ScopedDataPipeConsumerHandle body) override;
  void OnComplete(int request_id, const network::URLLoaderCompletionStatus& status) override;

  // Takes |downloaded_file_|.
  network::mojom::DownloadedTempFilePtr TakeDownloadedTempFile(int request_id);

 private:
  friend class DomainProcessHost;
  friend class Domain;

  bool NeedsStoringMessage(int request_id);
  void StoreAndDispatch(int request_id, std::unique_ptr<RouteRequestInfo::DeferredMessage> message);
  void OnConnectionClosed();

  RouteRequestInfo* GetRequest(int request) {
    base::AutoLock lock(requests_lock_);
    return requests_[request].get();
  }
  
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::WeakPtr<RouteRequestPeer> peer_;
  //common::mojom::RouteDispatcherPtr route_dispatcher_;
  common::mojom::RouteDispatcherAssociatedPtr route_dispatcher_;
  //mojo::Binding<common::mojom::RouteDispatcherClient> route_dispatcher_client_binding_;
  mojo::AssociatedBinding<common::mojom::RouteDispatcherClient> route_dispatcher_client_binding_;

  std::unordered_map<int, std::unique_ptr<RouteRequestInfo>> requests_;

  base::Lock requests_lock_;

  base::WeakPtrFactory<RouteDispatcherClient> weak_factory_;
};

}

#endif