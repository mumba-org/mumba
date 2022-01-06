// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_dispatcher_client.h"

#include <iterator>

#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "core/host/route/route_request_peer.h"
#include "core/host/route/route_response_body_consumer.h"
#include "net/url_request/redirect_info.h"

namespace host {

RouteRequestInfo::RouteRequestInfo(int request_id, base::WeakPtr<RouteRequestPeer> peer): 
  request_id(request_id),
  peer(std::move(peer)) {

}

RouteRequestInfo::~RouteRequestInfo() {
  if (body_consumer) {
    body_consumer->Cancel();
  }
}

class RouteRequestInfo::DeferredMessage {
 public:
  DeferredMessage() = default;
  virtual void HandleMessage(//ResourceDispatcher* dispatcher,
                             const base::WeakPtr<RouteRequestPeer>& peer,
                             int request_id) = 0;
  virtual bool IsCompletionMessage() const = 0;
  virtual ~DeferredMessage() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(DeferredMessage);
};

class RouteRequestInfo::DeferredOnReceiveResponse final
    : public RouteRequestInfo::DeferredMessage {
 public:
  explicit DeferredOnReceiveResponse(
      const network::ResourceResponseHead& response_head)
      : response_head_(response_head) {}

  void HandleMessage(
    //ResourceDispatcher* dispatcher, 
    const base::WeakPtr<RouteRequestPeer>& peer,
    int request_id) override {
   // DLOG(INFO) << "RouteDispatcherClient::OnReceivedResponse";
    //dispatcher->OnReceivedResponse(request_id, response_head_);
    peer->OnReceivedResponse(request_id, response_head_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const network::ResourceResponseHead response_head_;
};

class RouteRequestInfo::DeferredOnReceiveRedirect final
    : public RouteRequestInfo::DeferredMessage {
 public:
  DeferredOnReceiveRedirect(
      const net::RedirectInfo& redirect_info,
      const network::ResourceResponseHead& response_head,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : redirect_info_(redirect_info),
        response_head_(response_head),
        task_runner_(std::move(task_runner)) {}

  void HandleMessage(
      //ResourceDispatcher* dispatcher, 
      const base::WeakPtr<RouteRequestPeer>& peer,
      int request_id) override {
 //   DLOG(INFO) << "RouteDispatcherClient::OnOnReceiveRedirect";
    // dispatcher->OnReceivedRedirect(request_id, redirect_info_, response_head_,
    //                                task_runner_);
    peer->OnReceivedRedirect(request_id, 
                             redirect_info_, 
                             response_head_,
                             task_runner_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const net::RedirectInfo redirect_info_;
  const network::ResourceResponseHead response_head_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

class RouteRequestInfo::DeferredOnDataDownloaded final
    : public RouteRequestInfo::DeferredMessage {
 public:
  DeferredOnDataDownloaded(int64_t data_length, int64_t encoded_data_length)
      : data_length_(data_length), encoded_data_length_(encoded_data_length) {}

  void HandleMessage(
    //ResourceDispatcher* dispatcher, 
    const base::WeakPtr<RouteRequestPeer>& peer,
    int request_id) override {
   // DLOG(INFO) << "RouteDispatcherClient::OnDataDownloaded";
    // dispatcher->OnDownloadedData(request_id, data_length_,
    //                              encoded_data_length_);
    peer->OnDownloadedData(request_id, data_length_, encoded_data_length_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const int64_t data_length_;
  const int64_t encoded_data_length_;
};

class RouteRequestInfo::DeferredOnUploadProgress final
    : public RouteRequestInfo::DeferredMessage {
 public:
  DeferredOnUploadProgress(int64_t current, int64_t total)
      : current_(current), total_(total) {}

  void HandleMessage(
    //ResourceDispatcher* dispatcher, 
    const base::WeakPtr<RouteRequestPeer>& peer,
    int request_id) override {
  //  DLOG(INFO) << "RouteDispatcherClient::OnUploadProgress";
    //dispatcher->OnUploadProgress(request_id, current_, total_);
    peer->OnUploadProgress(request_id, current_, total_);
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const int64_t current_;
  const int64_t total_;
};

class RouteRequestInfo::DeferredOnReceiveCachedMetadata final
    : public RouteRequestInfo::DeferredMessage {
 public:
  explicit DeferredOnReceiveCachedMetadata(const std::vector<uint8_t>& data)
      : data_(data) {}

  void HandleMessage(
    //ResourceDispatcher* dispatcher, 
    const base::WeakPtr<RouteRequestPeer>& peer,
    int request_id) override {
  //  DLOG(INFO) << "RouteDispatcherClient::OnReceivedCachedMetadata";
    //dispatcher->OnReceivedCachedMetadata(request_id, data_);
    peer->OnReceivedCachedMetadata(request_id, data_, data_.size());
  }
  bool IsCompletionMessage() const override { return false; }

 private:
  const std::vector<uint8_t> data_;
};

class RouteRequestInfo::DeferredOnComplete final : public RouteRequestInfo::DeferredMessage {
 public:
  explicit DeferredOnComplete(const network::URLLoaderCompletionStatus& status)
      : status_(status) {}

  void HandleMessage(
    //ResourceDispatcher* dispatcher, 
    const base::WeakPtr<RouteRequestPeer>& peer,
    int request_id) override {
  //  DLOG(INFO) << "RouteDispatcherClient::OnRequestComplete";
    //dispatcher->OnRequestComplete(request_id, status_);
    peer->OnCompletedRequest(request_id, status_);
  }
  bool IsCompletionMessage() const override { return true; }

 private:
  const network::URLLoaderCompletionStatus status_;
};

RouteDispatcherClient::RouteDispatcherClient(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : task_runner_(std::move(task_runner)),
      route_dispatcher_client_binding_(this),
      weak_factory_(this) {}

RouteDispatcherClient::~RouteDispatcherClient() {
  
}

void RouteDispatcherClient::BindPeer(base::WeakPtr<RouteRequestPeer> peer) {
  peer_ = std::move(peer);
}

void RouteDispatcherClient::OnRequestCreated(int request_id) {
  std::unique_ptr<RouteRequestInfo> request = std::make_unique<RouteRequestInfo>(request_id, std::move(peer_));
  requests_.emplace(request_id, std::move(request));
}

void RouteDispatcherClient::OnRequestStarted(int request_id) {
  RouteRequestInfo* request = GetRequest(request_id);
  request->started = true;
}

void RouteDispatcherClient::SetDefersLoading(int request_id) {
  RouteRequestInfo* request = GetRequest(request_id);
  request->is_deferred = true;
  if (request->body_consumer)
    request->body_consumer->SetDefersLoading();
}

void RouteDispatcherClient::UnsetDefersLoading(int request_id) {
  RouteRequestInfo* request = GetRequest(request_id);
  request->is_deferred = false;

  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&RouteDispatcherClient::FlushDeferredMessages,
                                weak_factory_.GetWeakPtr(),
                                request_id));
}

void RouteDispatcherClient::FlushDeferredMessages(int request_id) {
  RouteRequestInfo* request = GetRequest(request_id);
  if (request->is_deferred)
    return;
  std::vector<std::unique_ptr<RouteRequestInfo::DeferredMessage>> messages;
  messages.swap(request->deferred_messages);
  bool has_completion_message = false;
  base::WeakPtr<RouteDispatcherClient> weak_this = weak_factory_.GetWeakPtr();
  // First, dispatch all messages excluding the followings:
  //  - response body (dispatched by |body_consumer_|)
  //  - transfer size change (dispatched later)
  //  - completion (dispatched by |body_consumer_| or dispatched later)
  for (size_t index = 0; index < messages.size(); ++index) {
    if (messages[index]->IsCompletionMessage()) {
      // The completion message arrives at the end of the message queue.
      DCHECK(!has_completion_message);
      DCHECK_EQ(index, messages.size() - 1);
      has_completion_message = true;
      break;
    }

    messages[index]->HandleMessage(
      //resource_dispatcher_, 
      request->peer,
      request_id);
    if (!weak_this)
      return;
    if (request->is_deferred) {
      request->deferred_messages.insert(
          request->deferred_messages.begin(),
          std::make_move_iterator(messages.begin()) + index + 1,
          std::make_move_iterator(messages.end()));
      return;
    }
  }

  // Dispatch the transfer size update.
  if (request->accumulated_transfer_size_diff_during_deferred > 0) {
    auto transfer_size_diff = request->accumulated_transfer_size_diff_during_deferred;
    request->accumulated_transfer_size_diff_during_deferred = 0;
    // resource_dispatcher_->OnTransferSizeUpdated(request_id_,
    //                                             transfer_size_diff);
    request->peer->OnTransferSizeUpdated(
      request_id, 
      transfer_size_diff);

    if (!weak_this)
      return;
    if (request->is_deferred) {
      if (has_completion_message) {
        DCHECK_GT(messages.size(), 0u);
        DCHECK(messages.back()->IsCompletionMessage());
        request->deferred_messages.emplace_back(std::move(messages.back()));
      }
      return;
    }
  }

  if (request->body_consumer) {
    // When we have |body_consumer_|, the completion message is dispatched by
    // it, not by this object.
    DCHECK(!has_completion_message);
    // Dispatch the response body.
    request->body_consumer->UnsetDefersLoading();
    return;
  }

  // Dispatch the completion message.
  if (has_completion_message) {
    DCHECK_GT(messages.size(), 0u);
    DCHECK(messages.back()->IsCompletionMessage());
    messages.back()->HandleMessage(request->peer, request_id);
  }
}

// void RouteDispatcherClient::Bind(
//   common::mojom::RouteDispatcherClientRequest route_dispatcher_client_request) {
void RouteDispatcherClient::Bind(
  common::mojom::RouteDispatcherClientAssociatedRequest route_dispatcher_client_request) {
  route_dispatcher_client_binding_.Bind(
    std::move(route_dispatcher_client_request), task_runner_);
  
  route_dispatcher_client_binding_.set_connection_error_handler(base::BindOnce(
      &RouteDispatcherClient::OnConnectionClosed, weak_factory_.GetWeakPtr()));
}

void RouteDispatcherClient::OnReceiveResponse(
    int request_id,
    const network::ResourceResponseHead& response_head,
    network::mojom::DownloadedTempFilePtr downloaded_file) {
  RouteRequestInfo* request = GetRequest(request_id);
  DCHECK(request);
  request->has_received_response = true;
  request->downloaded_file = std::move(downloaded_file);
  // if (NeedsStoringMessage(request_id)) {
  //   StoreAndDispatch(
  //     request_id,
  //     std::make_unique<RouteRequestInfo::DeferredOnReceiveResponse>(response_head));
  // } else {
    //resource_dispatcher_->OnReceivedResponse(request_id_, response_head);
  DCHECK(request->peer);
  request->peer->OnReceivedResponse(request_id, response_head);
  //}
}

void RouteDispatcherClient::OnReceiveRedirect(
    int request_id,
    const net::RedirectInfo& redirect_info,
    const network::ResourceResponseHead& response_head) {
  RouteRequestInfo* request = GetRequest(request_id);
  DCHECK(!request->has_received_response);
  DCHECK(!request->body_consumer);
  // if (NeedsStoringMessage(request_id)) {
  //   StoreAndDispatch(
  //     request_id,
  //     std::make_unique<RouteRequestInfo::DeferredOnReceiveRedirect>(
  //     redirect_info, response_head, task_runner_));
  // } else {
    //resource_dispatcher_->OnReceivedRedirect(request_id_, redirect_info,
    //                                         response_head, task_runner_);
    request->peer->OnReceivedRedirect(
      request_id, 
      redirect_info,
      response_head, 
      task_runner_);
  //}
}

void RouteDispatcherClient::OnDataDownloaded(
  int request_id,
  int64_t data_len,
  int64_t encoded_data_len) {
  RouteRequestInfo* request = GetRequest(request_id);
  if (NeedsStoringMessage(request_id)) {
    StoreAndDispatch(
      request_id,
      std::make_unique<RouteRequestInfo::DeferredOnDataDownloaded>(data_len, encoded_data_len));
  } else {
    //resource_dispatcher_->OnDownloadedData(request_id_, data_len,
    //                                       encoded_data_len);
    request->peer->OnDownloadedData(request_id, 
                                    data_len,
                                    encoded_data_len);
  }
}

void RouteDispatcherClient::OnUploadProgress(
  int request_id,
  int64_t current_position,
  int64_t total_size,
  OnUploadProgressCallback ack_callback) {
  RouteRequestInfo* request = GetRequest(request_id);
  if (NeedsStoringMessage(request_id)) {
    StoreAndDispatch(request_id, std::make_unique<RouteRequestInfo::DeferredOnUploadProgress>(
        current_position, total_size));
  } else {
    // resource_dispatcher_->OnUploadProgress(request_id_, current_position,
    //                                        total_size);
    request->peer->OnUploadProgress(request_id, 
                                    current_position,
                                    total_size);
  }
  std::move(ack_callback).Run();
}

void RouteDispatcherClient::OnReceiveCachedMetadata(
  int request_id,
  const std::vector<uint8_t>& data) {
  RouteRequestInfo* request = GetRequest(request_id);
  if (NeedsStoringMessage(request_id)) {
    StoreAndDispatch(request_id, std::make_unique<RouteRequestInfo::DeferredOnReceiveCachedMetadata>(data));
  } else {
    //resource_dispatcher_->OnReceivedCachedMetadata(request_id_, data);
    request->peer->OnReceivedCachedMetadata(request_id, data, data.size());
  }
}

void RouteDispatcherClient::OnTransferSizeUpdated(
  int request_id,
  int32_t transfer_size_diff) {
  RouteRequestInfo* request = GetRequest(request_id);
  if (request->is_deferred) {
    request->accumulated_transfer_size_diff_during_deferred += transfer_size_diff;
  } else {
    // resource_dispatcher_->OnTransferSizeUpdated(request_id_,
    //                                             transfer_size_diff);
    request->peer->OnTransferSizeUpdated(request_id, transfer_size_diff);
  }
}

void RouteDispatcherClient::OnStartLoadingResponseBody(
  int request_id,
  mojo::ScopedDataPipeConsumerHandle body) {
  
  RouteRequestInfo* request = GetRequest(request_id);
  DCHECK(!request->body_consumer);
  DCHECK(request->has_received_response);

  // if (request->pass_response_pipe_to_dispatcher) {
  //   request->peer->OnStartLoadingResponseBody(request_id,
  //                                             std::move(body));
  //   return;
  // }

  request->body_consumer = new RouteResponseBodyConsumer(
      request_id, 
      //resource_dispatcher_, 
      request->peer.get(),
      std::move(body), 
      task_runner_);

  if (request->is_deferred) {
    request->body_consumer->SetDefersLoading();
    return;
  }

  request->body_consumer->OnReadable(MOJO_RESULT_OK);
}

void RouteDispatcherClient::OnComplete(
  int request_id,
  const network::URLLoaderCompletionStatus& status) {
  RouteRequestInfo* request = GetRequest(request_id);
  request->has_received_complete = true;
  //if (!request->body_consumer) {
    //if (NeedsStoringMessage(request_id)) {
    //  StoreAndDispatch(request_id, std::make_unique<RouteRequestInfo::DeferredOnComplete>(status));
    //} else {
      //resource_dispatcher_->OnRequestComplete(request_id_, status);
  if (request->peer) {
    request->peer->OnCompletedRequest(request_id, status);
  }
    //}
      //return;
  //}
  //request->body_consumer->OnComplete(status);
}

network::mojom::DownloadedTempFilePtr
RouteDispatcherClient::TakeDownloadedTempFile(int request_id) {
  RouteRequestInfo* request = GetRequest(request_id);
  return std::move(request->downloaded_file);
}

bool RouteDispatcherClient::NeedsStoringMessage(int request_id) {
  RouteRequestInfo* request = GetRequest(request_id);
  return request->is_deferred || request->deferred_messages.size() > 0;
}

void RouteDispatcherClient::StoreAndDispatch(
  int request_id,
  std::unique_ptr<RouteRequestInfo::DeferredMessage> message) {
  DCHECK(NeedsStoringMessage(request_id));
  RouteRequestInfo* request = GetRequest(request_id);
  if (request->is_deferred) {
    request->deferred_messages.push_back(std::move(message));
  } else if (request->deferred_messages.size() > 0) {
    request->deferred_messages.push_back(std::move(message));
    FlushDeferredMessages(request_id);
  } else {
    NOTREACHED();
  }
}

void RouteDispatcherClient::OnConnectionClosed() {
  //DLOG(ERROR) << "RouteDispatcherClient::OnConnectionClosed: bad. theres only one dispatcher connection for all";
  // If the connection aborts before the load completes, mark it as aborted.
  // if (!has_received_complete_) {
  //   OnComplete(network::URLLoaderCompletionStatus(net::ERR_ABORTED));
  //   return;
  // }
}

}  // namespace host
