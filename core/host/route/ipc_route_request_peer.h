// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ROUTE_IPC_ROUTE_REQUEST_PEER_H_
#define MUMBA_HOST_ROUTE_IPC_ROUTE_REQUEST_PEER_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "core/host/route/route_request_peer.h"
#include "services/network/network_context.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/resource_scheduler_client.h"
#include "services/network/url_loader.h"
#include "services/network/url_loader_factory.h"

namespace net {
struct RedirectInfo;
}

namespace network {
struct ResourceResponseInfo;
struct URLLoaderCompletionStatus;
}

namespace host {

/*
 * IPCRouteRequestPeer serve as a proxy to the application process URLLoaderClient
 */
class IpcRouteRequestPeer : public RouteRequestPeer {
 public:
  IpcRouteRequestPeer(RouteRequestPeer::Delegate* delegate);
  ~IpcRouteRequestPeer() override;

  Delegate* GetDelegate() const override;
  
  void OnRequestStarted(int request_id) override;
  void OnUploadProgress(int request, uint64_t position, uint64_t size) override;
  bool OnReceivedRedirect(int request, const net::RedirectInfo& redirect_info, 
                          const network::ResourceResponseInfo& info,
                          scoped_refptr<base::SingleThreadTaskRunner> task_runner) override;
  void OnReceivedResponse(int request, const network::ResourceResponseHead& response_head) override;
  void OnStartLoadingResponseBody(int request, mojo::ScopedDataPipeConsumerHandle body) override;
  void OnDownloadedData(int request, int len, int encoded_data_length) override;
  void OnReceivedData(int request, std::unique_ptr<ReceivedData> data) override;
  void OnTransferSizeUpdated(int request, int transfer_size_diff) override;
  void OnReceivedCachedMetadata(int request, const std::vector<uint8_t>& data, int len) override;
  void OnCompletedRequest(int request, const network::URLLoaderCompletionStatus& status) override;

  base::WeakPtr<IpcRouteRequestPeer> GetWeakPtr();

private:

  RouteRequestPeer::Delegate* delegate_;

  base::WeakPtrFactory<IpcRouteRequestPeer> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(IpcRouteRequestPeer);
};

}  // namespace host

#endif
