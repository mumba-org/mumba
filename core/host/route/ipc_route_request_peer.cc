// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/ipc_route_request_peer.h"

#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "core/host/route/route_request_peer.h"
#include "core/host/route/route_response_body_consumer.h"
#include "net/url_request/redirect_info.h"

namespace host {

IpcRouteRequestPeer::IpcRouteRequestPeer(RouteRequestPeer::Delegate* delegate): 
  delegate_(delegate),
  weak_factory_(this) {
  
}

IpcRouteRequestPeer::~IpcRouteRequestPeer() {
}

RouteRequestPeer::Delegate* IpcRouteRequestPeer::GetDelegate() const {
  return delegate_;
}

base::WeakPtr<IpcRouteRequestPeer> IpcRouteRequestPeer::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

void IpcRouteRequestPeer::OnRequestStarted(int request_id) {
  delegate_->OnRequestStarted(request_id);
}

void IpcRouteRequestPeer::OnUploadProgress(int request, uint64_t position, uint64_t size) {
  delegate_->OnUploadProgress(request, position, size);
}

bool IpcRouteRequestPeer::OnReceivedRedirect(
  int request, 
  const net::RedirectInfo& redirect_info, 
  const network::ResourceResponseInfo& info,
  scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  return delegate_->OnReceivedRedirect(request, redirect_info, info, task_runner);
}

void IpcRouteRequestPeer::OnReceivedResponse(int request, const network::ResourceResponseHead& response_head) {
  delegate_->OnReceivedResponse(request, response_head);
}

void IpcRouteRequestPeer::OnStartLoadingResponseBody(int request, mojo::ScopedDataPipeConsumerHandle body) {
  delegate_->OnStartLoadingResponseBody(request, std::move(body));
}

void IpcRouteRequestPeer::OnDownloadedData(int request, int len, int encoded_data_length) {
  delegate_->OnDownloadedData(request, len, encoded_data_length);
}

void IpcRouteRequestPeer::OnReceivedData(int request, std::unique_ptr<ReceivedData> data) {
  delegate_->OnReceivedData(request, std::move(data));
}

void IpcRouteRequestPeer::OnTransferSizeUpdated(int request, int transfer_size_diff) {
  delegate_->OnTransferSizeUpdated(request, transfer_size_diff);
}

void IpcRouteRequestPeer::OnReceivedCachedMetadata(int request, const std::vector<uint8_t>& data, int len) {
  delegate_->OnReceivedCachedMetadata(request, data, len);
}

void IpcRouteRequestPeer::OnCompletedRequest(int request, const network::URLLoaderCompletionStatus& status) {
  delegate_->OnCompletedRequest(request, status);
}


}
