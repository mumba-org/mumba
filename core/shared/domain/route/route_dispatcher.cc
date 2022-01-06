// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/route/route_dispatcher.h"

#include <string>

#include "base/files/file.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/mime_sniffer.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_file_element_reader.h"
#include "net/cert/symantec_certs.h"
#include "net/ssl/client_cert_store.h"
#include "net/ssl/ssl_private_key.h"
#include "net/rpc/rpc_network_session.h"
#include "net/url_request/url_request_context.h"
#include "net/base/mime_util.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/log/net_log_with_source.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/mojom/chunked_data_pipe_getter.mojom.h"
#include "services/network/test_chunked_data_pipe_getter.h"
#include "services/network/chunked_data_pipe_upload_data_stream.h"
#include "services/network/data_pipe_element_reader.h"
#include "services/network/loader_util.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/net_adapters.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_response.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/resource_scheduler_client.h"

namespace domain {

namespace {

//constexpr size_t kDefaultAllocationSize = 16 * 1024;

void PopulateResourceResponse(RouteRequest* request,
                              bool is_load_timing_enabled,
                              network::ResourceResponse* response) {
  response->head.headers = request->GetResponseHeaders();
  request->GetCharset(&response->head.charset);
  response->head.content_length = request->GetExpectedContentSize();
  request->GetMimeType(&response->head.mime_type);
  net::HttpResponseInfo response_info = request->GetResponseInfo();
  response->head.request_time = response_info.request_time;
  response->head.response_time = response_info.response_time;
  response->head.was_fetched_via_spdy = response_info.was_fetched_via_spdy;
  response->head.was_alpn_negotiated = response_info.was_alpn_negotiated;
  response->head.alpn_negotiated_protocol = response_info.alpn_negotiated_protocol;
  response->head.connection_info = response_info.connection_info;
  response->head.socket_address = response_info.socket_address;
  response->head.was_fetched_via_proxy = response_info.was_fetched_via_proxy;
  response->head.network_accessed = response_info.network_accessed;

  response->head.effective_connection_type =
      net::EFFECTIVE_CONNECTION_TYPE_UNKNOWN;

  if (is_load_timing_enabled)
    request->GetLoadTimingInfo(&response->head.load_timing);

  response->head.request_start = request->GetCreationTime();
  response->head.response_start = base::TimeTicks::Now();
  response->head.encoded_data_length = request->GetTotalReceivedBytes();
}

network::ResourceRequest CreateResourceRequest(const std::string& method,
                                               const GURL& url) {
  network::ResourceRequest request;
  request.method = method;
  request.url = url;
  request.site_for_cookies = url;
  request.request_initiator = url::Origin::Create(url);
  request.is_main_frame = true;
  request.allow_download = true;
  return request;
}


scoped_refptr<network::HttpRawRequestResponseInfo> BuildRawRequestResponseInfo(
    RouteRequest& request,
    const net::HttpRawRequestHeaders& raw_request_headers,
    const net::HttpResponseHeaders* raw_response_headers) {
  scoped_refptr<network::HttpRawRequestResponseInfo> info =
      new network::HttpRawRequestResponseInfo();

  const net::HttpResponseInfo& response_info = request.GetResponseInfo();
  // Unparsed headers only make sense if they were sent as text, i.e. HTTP 1.x.
  bool report_headers_text =
      !response_info.DidUseQuic() && !response_info.was_fetched_via_spdy;

  for (const auto& pair : raw_request_headers.headers())
    info->request_headers.push_back(pair);
  std::string request_line = raw_request_headers.request_line();
  if (report_headers_text && !request_line.empty()) {
    std::string text = std::move(request_line);
    for (const auto& pair : raw_request_headers.headers()) {
      if (!pair.second.empty()) {
        base::StringAppendF(&text, "%s: %s\r\n", pair.first.c_str(),
                            pair.second.c_str());
      } else {
        base::StringAppendF(&text, "%s:\r\n", pair.first.c_str());
      }
    }
    info->request_headers_text = std::move(text);
  }

  if (!raw_response_headers)
    raw_response_headers = request.GetResponseHeaders();
  if (raw_response_headers) {
    info->http_status_code = raw_response_headers->response_code();
    info->http_status_text = raw_response_headers->GetStatusText();

    std::string name;
    std::string value;
    for (size_t it = 0;
         raw_response_headers->EnumerateHeaderLines(&it, &name, &value);) {
      info->response_headers.push_back(std::make_pair(name, value));
    }
    if (report_headers_text) {
      info->response_headers_text =
          net::HttpUtil::ConvertHeadersBackToHTTPResponse(
              raw_response_headers->raw_headers());
    }
  }
  return info;
}


}

RouteResponse::RouteResponse(
    const network::ResourceRequest& request,
    bool report_raw_headers):
     is_load_timing_enabled(request.enable_load_timing),
     keepalive(request.keepalive),
     writable_handle_watcher(FROM_HERE,
                              mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                              base::SequencedTaskRunnerHandle::Get()),
     writable_handle_closed_watcher(FROM_HERE,
                                 mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                                 base::SequencedTaskRunnerHandle::Get()),
     readable_handle_watcher(FROM_HERE,
                              mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                              base::SequencedTaskRunnerHandle::Get()),
     readable_handle_closed_watcher(FROM_HERE,
                                 mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                                 base::SequencedTaskRunnerHandle::Get()), 
     report_raw_headers(report_raw_headers) {

}

RouteDispatcher::RouteDispatcher(): 
      delegate_(nullptr),
      binding_(this),
      next_request_id_(1),
      weak_ptr_factory_(this) {
  
  // GetMimeTypeFromExtension
  //base::ScopedAllowBlockingForTesting allow;

  // std::string mime_type;
  // std::string extension = request.url.spec();
  // auto offset = extension.find_last_of(".");
  // if (offset != std::string::npos) {
  //   extension = extension.substr(offset + 1);
  // } else {
  //   extension = "html";
  // }
  // net::GetMimeTypeFromExtension(FILE_PATH_LITERAL(extension), &mime_type);

  // net::HttpRequestHeaders headers = request.headers;
  // headers.SetHeader("mime-type", mime_type);
  
  // delegate_->SetExtraRequestHeaders(this, headers);
  //request_ = delegate_->CreateRequest(this);
  //request_->Start();
}

void RouteDispatcher::Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  task_runner_ = task_runner;
  impl_task_runner_ = base::CreateSequencedTaskRunnerWithTraits({base::MayBlock(), base::WithBaseSyncPrimitives()});
}

// void RouteDispatcher::Bind(common::mojom::RouteDispatcherRequest route_dispatcher_request) {
//   binding_.Bind(std::move(route_dispatcher_request));
// }

void RouteDispatcher::Bind(common::mojom::RouteDispatcherAssociatedRequest route_dispatcher_request) {
  binding_.Bind(std::move(route_dispatcher_request));
  binding_.set_connection_error_handler(
    base::BindOnce(&RouteDispatcher::OnConnectionError,
                   base::Unretained(this)));
}

RouteDispatcher::~RouteDispatcher() {
  
}

void RouteDispatcher::StartRequest(int request_id, const std::string& url, mojo::ScopedDataPipeConsumerHandle receive_handle, mojo::ScopedDataPipeProducerHandle send_handle) {
  DCHECK(delegate_);
  auto owned_request = delegate_->CreateRequest(this, url, request_id);
  
  // check if the id is not reused somehow
  RouteRequest* checking = GetRequest(request_id);
  DCHECK(!checking);

  RouteRequest* request = owned_request.get();
  requests_.emplace(std::make_pair(request_id, std::move(owned_request)));

  std::unique_ptr<mojo::DataPipe> pipe = std::make_unique<mojo::DataPipe>();
  pipe->consumer_handle = std::move(receive_handle);
  pipe->producer_handle = std::move(send_handle);

  response_bodies_.emplace(std::make_pair(request_id, std::move(pipe)));
  
  impl_task_runner_->PostTask(FROM_HERE, 
                              base::BindOnce(&RouteDispatcher::StartOnImplThread, 
                                              base::Unretained(this),
                                              base::Unretained(request)));
}

void RouteDispatcher::ResumeStart(int request_id) {
  RouteRequest* request = GetRequest(request_id);
  if (!request) {
    return;
  }
  impl_task_runner_->PostTask(FROM_HERE, 
                              base::BindOnce(&RouteDispatcher::StartOnImplThread, 
                                              base::Unretained(this),
                                              base::Unretained(request)));
}

void RouteDispatcher::StartOnImplThread(RouteRequest* request) {
  request->Start(
    base::BindOnce(&RouteDispatcher::OnRequestStarted,
                    base::Unretained(this),
                    base::Unretained(request)));
}

void RouteDispatcher::OnRequestStarted(RouteRequest* request, int net_error) {
  task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&RouteDispatcher::OnResponseStarted,
                   base::Unretained(this),
                   base::Unretained(request), 
                   net_error));
}

void RouteDispatcher::OnResponseStarted(RouteRequest* request, int net_error) {
  int request_id = request->id();

  route_dispatcher_client_->OnRequestStarted(request_id);

  if (net_error != net::OK) {
    NotifyCompleted(request_id, net_error);
    // |this| may have been deleted.
    return;
  }

  network::ResourceRequest resource_request = CreateResourceRequest(request->method(), request->url());

  std::unique_ptr<RouteResponse> owned_route_response = std::make_unique<RouteResponse>(resource_request, false);
  RouteResponse* route_response = owned_route_response.get();
  
  auto response_body_it = response_bodies_.find(request_id);
  DCHECK(response_body_it != response_bodies_.end());
  route_response->body_sender = std::move(response_body_it->second->producer_handle);
  route_response->body_receiver = std::move(response_body_it->second->consumer_handle);
  response_bodies_.erase(response_body_it);

  responses_.emplace(std::make_pair(request_id, std::move(owned_route_response)));

  // Do not account header bytes when reporting received body bytes to client.
  route_response->reported_total_encoded_bytes = requests_[request_id]->GetTotalReceivedBytes();

  route_response->response = new network::ResourceResponse();
  PopulateResourceResponse(
      requests_[request_id].get(), 
      route_response->is_load_timing_enabled,
      route_response->response.get());

  if (route_response->report_raw_headers) {
    route_response->response->head.raw_request_response_info = BuildRawRequestResponseInfo(
      *requests_[request_id], 
      route_response->raw_request_headers, 
      route_response->raw_response_headers.get());
    route_response->raw_request_headers = net::HttpRawRequestHeaders();
    route_response->raw_response_headers = nullptr;
  }

  route_response->writable_handle_closed_watcher.Watch(
      route_response->body_sender.get(), MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::Bind(&RouteDispatcher::OnResponseBodySenderStreamClosed,
                 base::Unretained(this),
                 request_id));
  route_response->writable_handle_closed_watcher.ArmOrNotify();


  route_response->readable_handle_closed_watcher.Watch(
      route_response->body_receiver.get(), MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::Bind(&RouteDispatcher::OnResponseBodyReceiverStreamClosed,
                 base::Unretained(this),
                 request_id));
  route_response->readable_handle_closed_watcher.ArmOrNotify();

  route_response->writable_handle_watcher.Watch(
      route_response->body_sender.get(), MOJO_HANDLE_SIGNAL_WRITABLE,
      base::Bind(&RouteDispatcher::OnResponseBodySenderStreamWritable,
                 base::Unretained(this),
                 request_id));

  route_response->readable_handle_watcher.Watch(
      route_response->body_receiver.get(), MOJO_HANDLE_SIGNAL_READABLE,
      base::Bind(&RouteDispatcher::OnResponseBodyReceiverStreamReadable,
                 base::Unretained(this),
                 request_id));

  //if (!(options_ & network::mojom::kURLLoadOptionSniffMimeType)) { //||!ShouldSniffContent(url_request_.get(), response_.get())) {
  SendResponseToClient(request_id);
  //}

  // Start reading...
  ReadMore(request_id);
}

void RouteDispatcher::OnReadCompleted(RouteRequest* request, int bytes_read) {
  //DLOG(INFO) << "RouteDispatcher::OnReadCompleted: bytes = " << bytes_read;
  DidRead(request->id(), bytes_read, false);
  // |this| may have been deleted.
}

void RouteDispatcher::OnResponseBodySenderStreamClosed(int request_id, MojoResult result) {
  RouteRequest* request = GetRequest(request_id);
  if (!request) {
    return;
  }
  NotifyCompleted(request_id, net::ERR_FAILED);
}

void RouteDispatcher::OnResponseBodyReceiverStreamClosed(int request_id, MojoResult result) {
  RouteRequest* request = GetRequest(request_id);
  if (!request) {
    return;
  }
  NotifyCompleted(request_id, net::ERR_FAILED);
}

void RouteDispatcher::OnResponseBodySenderStreamWritable(int request_id, MojoResult result) {
  if (result != MOJO_RESULT_OK) {
    NotifyCompleted(request_id, net::ERR_FAILED);
    return;
  }
  ReadMore(request_id);
}

void RouteDispatcher::OnResponseBodyReceiverStreamReadable(int request_id, MojoResult result) {
  //DLOG(INFO) << "RouteDispatcher::OnResponseBodyReceiverStreamReadable: We dont do nothing here";
}

void RouteDispatcher::FollowRedirect(int request_id) {
  //DLOG(INFO) << "RouteDispatcher::FollowRedirect";
  
  // if (!url_request_) {
  //   NotifyCompleted(net::ERR_UNEXPECTED);
  //   // |this| may have been deleted.
  //   return;
  // }
  RouteRequest* request = GetRequest(request_id);
  request->FollowDeferredRedirect();
}

void RouteDispatcher::ProceedWithResponse(int request_id) {
  //DLOG(INFO) << "RouteDispatcher::ProceedWithResponse: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RouteDispatcher::SetPriority(int request_id,
                                  net::RequestPriority priority,
                                  int32_t intra_priority_value) {
  //DLOG(INFO) << "RouteDispatcher::SetPriority: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RouteDispatcher::PauseReadingBodyFromNet(int request_id) {
  //DLOG(INFO) << "RouteDispatcher::PauseReadingBodyFromNet: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RouteDispatcher::ResumeReadingBodyFromNet(int request_id) {
  //DLOG(INFO) << "RouteDispatcher::ResumeReadingBodyFromNet: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RouteDispatcher::GetRouteHeader(const std::string& url, GetRouteHeaderCallback callback) {
  //RouteRequest* request = GetRequest(request_id);
  //request->GetRouteHeader(url, std::move(callback));
  delegate_->GetRouteHeader(url, std::move(callback));
}

void RouteDispatcher::LookupRoute(const std::string& query, LookupRouteCallback callback) {
  delegate_->LookupRoute(query, std::move(callback));
}

void RouteDispatcher::LookupRouteByPath(const std::string& path, LookupRouteByPathCallback callback) {
  delegate_->LookupRouteByPath(path, std::move(callback));
}

void RouteDispatcher::LookupRouteByUrl(const GURL& url, LookupRouteByUrlCallback callback) {
  delegate_->LookupRouteByUrl(url, std::move(callback));
}

void RouteDispatcher::LookupRouteByUUID(const std::string& uuid, LookupRouteByUUIDCallback callback) {
  delegate_->LookupRouteByUUID(uuid, std::move(callback));
}

void RouteDispatcher::GetRouteCount(GetRouteCountCallback callback) {
  delegate_->GetRouteCount(std::move(callback));
}

void RouteDispatcher::Subscribe(common::mojom::RouteSubscriberPtr subscriber, SubscribeCallback callback) {
  delegate_->Subscribe(std::move(subscriber), std::move(callback));
}

void RouteDispatcher::Unsubscribe(int32_t subscriber_id) {
  delegate_->Unsubscribe(subscriber_id);
}

void RouteDispatcher::ReadMore(int request_id) {
  RouteRequest* request = GetRequest(request_id);
  RouteResponse* response = GetResponse(request_id);
  
  // Once the MIME type is sniffed, all data is sent as soon as it is read from
  // the network.
  DCHECK(response->consumer_handle.is_valid() || !response->pending_write);

  if (!response->pending_write.get()) {
    // TODO: we should use the abstractions in MojoAsyncResourceHandler.
    DCHECK_EQ(0u, response->pending_write_buffer_offset);
    MojoResult result = network::NetToMojoPendingBuffer::BeginWrite(
        &response->body_sender, &response->pending_write, &response->pending_write_buffer_size);
    if (result != MOJO_RESULT_OK && result != MOJO_RESULT_SHOULD_WAIT) {
      // The response body stream is in a bad state. Bail.
      NotifyCompleted(request_id, net::ERR_FAILED);
      return;
    }

    DCHECK_GT(static_cast<uint32_t>(std::numeric_limits<int>::max()),
              response->pending_write_buffer_size);
    if (response->consumer_handle.is_valid()) {
      DCHECK_GE(response->pending_write_buffer_size,
                static_cast<uint32_t>(net::kMaxBytesToSniff));
    }
    if (result == MOJO_RESULT_SHOULD_WAIT) {
      // The pipe is full. We need to wait for it to have more space.
      response->writable_handle_watcher.ArmOrNotify();
      return;
    }
  }

  auto buf = base::MakeRefCounted<network::NetToMojoIOBuffer>(
      response->pending_write.get(), response->pending_write_buffer_offset);


  // Read should not block the main thread, giving this is what the client code
  // should do, here we dispatch the read into another thread 
  impl_task_runner_->PostTask(FROM_HERE, 
                              base::BindOnce(&RouteDispatcher::ReadOnImplThread, 
                                              base::Unretained(this),
                                              base::Unretained(request),
                                              base::Unretained(response),
                                              buf));
}

void RouteDispatcher::ReadOnImplThread(RouteRequest* request, RouteResponse* response, scoped_refptr<network::NetToMojoIOBuffer> buf) {
  int bytes_read;
  request->Read(buf.get(),
                static_cast<int>(response->pending_write_buffer_size -
                                 response->pending_write_buffer_offset),
                &bytes_read);

  task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(&RouteDispatcher::DidRead,
                   base::Unretained(this),
                   request->id(), 
                   bytes_read, 
                   true));
}

void RouteDispatcher::DidRead(int request_id, int num_bytes, bool completed_synchronously) {
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  RouteResponse* response = GetResponse(request_id);
  RouteRequest* request = GetRequest(request_id);

  if (num_bytes > 0) {
    response->pending_write_buffer_offset += num_bytes;

    // Only notify client of download progress in case DevTools are attached
    // and we're done sniffing and started sending response.
    if (response->report_raw_headers && !response->consumer_handle.is_valid()) {
      int64_t total_encoded_bytes = request->GetTotalReceivedBytes();
      int64_t delta = total_encoded_bytes - response->reported_total_encoded_bytes;
      DCHECK_LE(0, delta);
      if (delta) {
        //DLOG(INFO) << "RouteDispatcher::DidRead: calling route_dispatcher_client_->OnTransferSizeUpdated(delta). delta = " << delta;
        route_dispatcher_client_->OnTransferSizeUpdated(request_id, delta);
      }
      response->reported_total_encoded_bytes = total_encoded_bytes;
    }
  }
  //if (update_body_read_before_paused_) {
  //  update_body_read_before_paused_ = false;
  //  body_read_before_paused_ = url_request_->GetRawBodyBytes();
  //}

  bool complete_read = true;
  // if (response->consumer_handle.is_valid()) {
  //   const std::string& type_hint = response->response->head.mime_type;
  //   std::string new_type;
  //   bool made_final_decision = net::SniffMimeType(
  //       response->pending_write->buffer(), 
  //       response->pending_write_buffer_offset,
  //       request->url(), 
  //       type_hint,
  //       net::ForceSniffFileUrlsForHtml::kDisabled, &new_type);
    
  //   // SniffMimeType() returns false if there is not enough data to determine
  //   // the mime type. However, even if it returns false, it returns a new type
  //   // that is probably better than the current one.
  //   response->response->head.mime_type.assign(new_type);

  //   if (!made_final_decision) {
  //     complete_read = false;
  //   }
    
    
  //   // if (route_entry_->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM ||
  //   //     route_entry_->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM) {
  //   //   //DLOG(INFO) << "RouteDispatcher::DidRead: server or bidi stream method. sending response to client now";
  //   //   complete_read = true;
  //   //   SendResponseToClient();
  //   // }
  // }

  if (request->status() != net::OK || num_bytes == 0) {
    CompletePendingWrite(request_id);
    NotifyCompleted(request_id, request->status());
    // |this| will have been deleted.
    return;
  }

  if (complete_read) {
    CompletePendingWrite(request_id);
  }

  if (completed_synchronously) {
   // //DLOG(INFO) << "RouteDispatcher::DidRead: completed_synchronously = true. calling ReadMore()";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::BindOnce(&RouteDispatcher::ReadMore, weak_ptr_factory_.GetWeakPtr(), request_id));
  } else {
   // //DLOG(INFO) << "RouteDispatcher::DidRead: completed_synchronously = false. calling ReadMore()";
    ReadMore(request_id);
  }
}

void RouteDispatcher::NotifyCompleted(int request_id, int error_code) {
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  RouteResponse* response = GetResponse(request_id);
  RouteRequest* request = GetRequest(request_id);

  if (!request || !response) {
    return;
  }
  
  request->Complete(error_code);
  
  if (response->consumer_handle.is_valid()) {
    SendResponseToClient(request_id);
  }

  network::URLLoaderCompletionStatus status;
  status.error_code = error_code;
  status.exists_in_cache = false;//url_request_->response_info().was_cached;
  status.completion_time = base::TimeTicks::Now();
  status.encoded_data_length = request->GetTotalReceivedBytes();
  status.encoded_body_length = request->GetRawBodyBytes();
  status.decoded_body_length = response->total_written_bytes;

  route_dispatcher_client_->OnComplete(request_id, status);
  delegate_->OnComplete(this, request_id, status);
  // FIXME: see if this is what we want
  //        the error was that we are reusing the same loader
  //        for more than one resource and this number get down
  //        the pipe as the received bytes and being a sum of all the resources
  //        is not really what we want
  //total_written_bytes_ = 0;
  DropRequestAndResponse(request_id);
}

void RouteDispatcher::OnConnectionError() {
  //DLOG(INFO) << "RouteDispatcher::OnConnectionError: calling NotifyCompleted(net::ERR_FAILED)";
  
  //NotifyCompleted(net::ERR_FAILED);
  // task_runner_->PostTask(
  //       FROM_HERE,
  //       base::BindOnce(&RouteDispatcher::NotifyCompleted, weak_ptr_factory_.GetWeakPtr(), net::ERR_FAILED));
}

void RouteDispatcher::SendResponseToClient(int request_id) {
  //DLOG(INFO) << "RouteDispatcher::SendResponseToClient";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  RouteResponse* response = GetResponse(request_id);
  //DLOG(INFO) << "RouteDispatcher::SendResponseToClient: calling route_dispatcher_client_->OnReceiveResponse()";
  route_dispatcher_client_->OnReceiveResponse(request_id, response->response->head, nullptr);

  net::IOBufferWithSize* metadata = nullptr;//url_request_->response_info().metadata.get();
  if (metadata) {
    //DLOG(INFO) << "RouteDispatcher::SendResponseToClient: metadata! calling route_dispatcher_client_->OnReceiveCachedMetadata()";
    const uint8_t* data = reinterpret_cast<const uint8_t*>(metadata->data());

    route_dispatcher_client_->OnReceiveCachedMetadata(
        request_id, std::vector<uint8_t>(data, data + metadata->size()));
  }

  //DLOG(INFO) << "RouteDispatcher::SendResponseToClient: calling route_dispatcher_client_->OnStartLoadingResponseBody()";
 // route_dispatcher_client_->OnStartLoadingResponseBody(request_id, std::move(response->consumer_handle));
  response->response = nullptr;
}

void RouteDispatcher::SetRawResponseHeaders(int request_id, scoped_refptr<const net::HttpResponseHeaders> headers) {
  //DLOG(INFO) << "RouteDispatcher::SetRawResponseHeaders";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  RouteResponse* response = GetResponse(request_id);
  response->raw_response_headers = headers;
}

void RouteDispatcher::CompletePendingWrite(int request_id) {
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  RouteResponse* response = GetResponse(request_id);

  response->body_sender =
      response->pending_write->Complete(response->pending_write_buffer_offset);
  response->total_written_bytes += response->pending_write_buffer_offset;
  response->pending_write = nullptr;
  response->pending_write_buffer_offset = 0;
}

}