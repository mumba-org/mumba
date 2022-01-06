// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/ipc_url_loader.h"

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
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
#include "core/host/route/route_dispatcher_client.h"
#include "core/host/application/domain.h"
#include "services/network/chunked_data_pipe_upload_data_stream.h"
#include "services/network/data_pipe_element_reader.h"
#include "services/network/loader_util.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/net_adapters.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_response.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/resource_scheduler_client.h"

namespace host {

namespace {

constexpr size_t kDefaultAllocationSize = 16 * 1024;

void PopulateResourceResponse(RouteRequest* request,
                              bool is_load_timing_enabled,
                              bool include_ssl_info,
                              network::ResourceResponse* response) {
  response->head.request_time = request->request_time();
  response->head.response_time = request->response_time();
  response->head.headers = request->response_headers();
  request->GetCharset(&response->head.charset);
  response->head.content_length = request->GetExpectedContentSize();
  request->GetMimeType(&response->head.mime_type);

  network::ResourceResponseInfo response_info = request->response_info();
  response->head.was_fetched_via_spdy = response_info.was_fetched_via_spdy;
  response->head.was_alpn_negotiated = response_info.was_alpn_negotiated;
  response->head.alpn_negotiated_protocol =
      response_info.alpn_negotiated_protocol;
  response->head.connection_info = response_info.connection_info;
  response->head.socket_address = response_info.socket_address;
  response->head.was_fetched_via_proxy = request->was_fetched_via_proxy();
  response->head.network_accessed = response_info.network_accessed;

  response->head.effective_connection_type =
      net::EFFECTIVE_CONNECTION_TYPE_UNKNOWN;

  if (is_load_timing_enabled)
    request->GetLoadTimingInfo(&response->head.load_timing);

  response->head.request_start = request->creation_time();
  response->head.response_start = base::TimeTicks::Now();
  response->head.encoded_data_length = request->GetTotalReceivedBytes();
}

}

IpcURLLoader::IpcURLLoader(
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
    uint32_t request_id): 
      task_runner_(task_runner),
      url_request_context_(url_request_context),
      domain_(domain),
      route_registry_(route_registry),
      route_entry_(route_entry),
      delete_callback_(std::move(delete_callback)),
      options_(options),
      is_load_timing_enabled_(request.enable_load_timing),
      keepalive_(request.keepalive),
      binding_(this, std::move(url_loader_request)),
      url_loader_client_(std::move(url_loader_client)),
      writable_handle_watcher_(FROM_HERE,
                              mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                              base::SequencedTaskRunnerHandle::Get()),
      peer_closed_handle_watcher_(FROM_HERE,
                                  mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                                  base::SequencedTaskRunnerHandle::Get()),
      report_raw_headers_(report_raw_headers),
      weak_ptr_factory_(this) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  // GetMimeTypeFromExtension
  //base::ScopedAllowBlockingForTesting allow;

  binding_.set_connection_error_handler(
    base::BindOnce(&IpcURLLoader::OnConnectionError, base::Unretained(this)));

  if (!route_entry_) {
    route_entry_ = route_registry_->model()->GetEntry(request.url);
  }
  DCHECK(route_entry_);

  last_url_ = request.url;
  
  // url_request_ = url_request_context_->CreateRequest(
  //     GURL(url), request.priority, this, traffic_annotation);

  route_request_ = std::make_unique<RouteRequest>(request_id, weak_ptr_factory_.GetWeakPtr(), domain_->GetRouteDispatcherClient(), request.url, route_task_runner);
  
  // // we are bending the rules by using method here to mean something else
  // // but this will route to the rpc pipe on the url reuest loader
  // url_request_->set_method(GetMethodTypeStringFromMethodType(route_entry_->rpc_method_type()));
  // url_request_->set_initiator(request.request_initiator);
  // url_request_->SetLoadFlags(request.load_flags);
  
  // if (report_raw_headers_) {
  //   url_request_->SetRequestHeadersCallback(
  //       base::Bind(&net::HttpRawRequestHeaders::Assign,
  //                  base::Unretained(&raw_request_headers_)));
  //   url_request_->SetResponseHeadersCallback(
  //       base::Bind(&IpcURLLoader::SetRawResponseHeaders, base::Unretained(this)));
  // }

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
  // url_request_->SetExtraRequestHeaders(headers);
  // url_request_->Start();
  route_request_->Start();
}

// RouteDispatcher
//  + StartRequest(string url);
//  + GetRouteHead(int32 request_id, string url) => (network.mojom.URLResponseHead head);
//  + FollowRedirect(int32 request_id);
//  + ProceedWithResponse(int32 request_id);
//  + SetPriority(int32 request_id, network.mojom.RequestPriority priority, int32 intra_priority_value);
//  + PauseReadingBodyFromNet(int32 request_id);
//  + ResumeReadingBodyFromNet(int32 request_id);

IpcURLLoader::~IpcURLLoader() {
  //DLOG(INFO) << "~IpcURLLoader";
  if (keepalive_) {
    return;
  }
  url_request_context_ = nullptr;
  domain_ = nullptr;
  options_ = 0;
  is_load_timing_enabled_ = false;
}

void IpcURLLoader::ResumeStart() {
  route_request_->Start();
}

void IpcURLLoader::OnResponseStarted(RouteRequest* request, int net_error) {
  //DLOG(INFO) << "IpcURLLoader::OnResponseStarted: " << net_error;
  //DCHECK(url_request == url_request_.get());

  if (net_error != net::OK) {
    NotifyCompleted(net_error);
    // |this| may have been deleted.
    return;
  }

  // Do not account header bytes when reporting received body bytes to client.
  reported_total_encoded_bytes_ = route_request_->GetTotalReceivedBytes();

  response_ = new network::ResourceResponse();
  
  // FIXME: put this back
  PopulateResourceResponse(
    route_request_.get(), is_load_timing_enabled_,
    options_ & network::mojom::kURLLoadOptionSendSSLInfoWithResponse, response_.get());
  
  // if (report_raw_headers_) {
  //   response_->head.raw_request_response_info = network::BuildRawRequestResponseInfo(
  //       *url_request_, raw_request_headers_, raw_response_headers_.get());
  //   raw_request_headers_ = net::HttpRawRequestHeaders();
  //   raw_response_headers_ = nullptr;
  // }

  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(MojoCreateDataPipeOptions);
  options.flags = MOJO_CREATE_DATA_PIPE_OPTIONS_FLAG_NONE;
  options.element_num_bytes = 1;
  options.capacity_num_bytes = kDefaultAllocationSize;
  MojoResult result =
      mojo::CreateDataPipe(&options, &response_body_stream_, &consumer_handle_);
  if (result != MOJO_RESULT_OK) {
    NotifyCompleted(net::ERR_INSUFFICIENT_RESOURCES);
    return;
  }
  peer_closed_handle_watcher_.Watch(
      response_body_stream_.get(), MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::Bind(&IpcURLLoader::OnResponseBodyStreamConsumerClosed,
                 base::Unretained(this)));
  peer_closed_handle_watcher_.ArmOrNotify();

  writable_handle_watcher_.Watch(
      response_body_stream_.get(), MOJO_HANDLE_SIGNAL_WRITABLE,
      base::Bind(&IpcURLLoader::OnResponseBodyStreamReady,
                 base::Unretained(this)));

  // if (!(options_ & network::mojom::kURLLoadOptionSniffMimeType) ||
  //      !ShouldSniffContent(request_.get(), response_.get())) {
  //   SendResponseToClient();
  // }

  // Start reading...
  ReadMore();
}

void IpcURLLoader::OnReadCompleted(RouteRequest* request, int bytes_read) {
  DidRead(bytes_read, false);
  // |this| may have been deleted.
}

void IpcURLLoader::OnResponseBodyStreamConsumerClosed(MojoResult result) {
  //DLOG(INFO) << "\n\nIpcURLLoader::OnResponseBodyStreamConsumerClosed\n\n";
  NotifyCompleted(net::ERR_FAILED);
}

void IpcURLLoader::OnStreamReadDataAvailable(RouteRequest* request, int bytes_read) {
  //OnResponseBodyStreamReady(static_cast<MojoResult>(net_error));
  if (bytes_read == net::ERR_FAILED) {
    NotifyCompleted(net::ERR_FAILED);
    return;
  }
  ReadMore();
  //DidRead(bytes_read, false);
}

void IpcURLLoader::OnResponseBodyStreamReady(MojoResult result) {
  
  if (result != MOJO_RESULT_OK) {
    NotifyCompleted(net::ERR_FAILED);
    return;
  }

  ReadMore();
}

void IpcURLLoader::DeleteSelf() {
  std::move(delete_callback_).Run(this);
}

void IpcURLLoader::FollowRedirect() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  if (!route_request_->route_dispatcher_client()) {
    NotifyCompleted(net::ERR_UNEXPECTED);
    // |this| may have been deleted.
    return;
  }

  //url_request_->FollowDeferredRedirect();
}

void IpcURLLoader::ProceedWithResponse() {
  //DLOG(INFO) << "IpcURLLoader::ProceedWithResponse: NOT IMPLEMENTED";
  //NOTREACHED();
}

void IpcURLLoader::SetPriority(net::RequestPriority priority,
                               int32_t intra_priority_value) {
  //DLOG(INFO) << "IpcURLLoader::SetPriority: NOT IMPLEMENTED";
  //NOTREACHED();
}

void IpcURLLoader::PauseReadingBodyFromNet() {
  //DLOG(INFO) << "IpcURLLoader::PauseReadingBodyFromNet: NOT IMPLEMENTED";
  //NOTREACHED();
}

void IpcURLLoader::ResumeReadingBodyFromNet() {
  //DLOG(INFO) << "IpcURLLoader::ResumeReadingBodyFromNet: NOT IMPLEMENTED";
  //NOTREACHED();
}

void IpcURLLoader::ReadMore() {
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  // Once the MIME type is sniffed, all data is sent as soon as it is read from
  // the network.
  //DCHECK(consumer_handle_.is_valid() || !pending_write_);

  if (!pending_write_.get()) {
    // TODO: we should use the abstractions in MojoAsyncResourceHandler.
    DCHECK_EQ(0u, pending_write_buffer_offset_);
    MojoResult result = network::NetToMojoPendingBuffer::BeginWrite(
        &response_body_stream_, &pending_write_, &pending_write_buffer_size_);
    if (result != MOJO_RESULT_OK && result != MOJO_RESULT_SHOULD_WAIT) {
      // The response body stream is in a bad state. Bail.
      NotifyCompleted(net::ERR_FAILED);
      return;
    }

    DCHECK_GT(static_cast<uint32_t>(std::numeric_limits<int>::max()),
              pending_write_buffer_size_);
    // if (consumer_handle_.is_valid()) {
    //   DCHECK_GE(pending_write_buffer_size_,
    //             static_cast<uint32_t>(net::kMaxBytesToSniff));
    // }
    if (result == MOJO_RESULT_SHOULD_WAIT) {
      // The pipe is full. We need to wait for it to have more space.
      writable_handle_watcher_.ArmOrNotify();
      return;
    }
  }

  auto buf = base::MakeRefCounted<network::NetToMojoIOBuffer>(
    pending_write_.get(), pending_write_buffer_offset_);
  
  // url_request_->Read(buf.get(),
  //                    static_cast<int>(pending_write_buffer_size_ -
  //                                     pending_write_buffer_offset_),
  //                    &bytes_read);

  route_request_->Read(buf.get(),
                       static_cast<int>(pending_write_buffer_size_ -
                                        pending_write_buffer_offset_),
                       base::BindOnce(&IpcURLLoader::OnRead, base::Unretained(this)));

  // DLOG(INFO) << "\n\nIpcURLLoader::ReadMore:\n pending_write_buffer_offset_ = " << 
  //   pending_write_buffer_offset_ << "\n pending_write_buffer_size_ = " << pending_write_buffer_size_ << "\n " <<
  //   "pending_write_buffer_size_ - pending_write_buffer_offset_ = " << pending_write_buffer_size_ - pending_write_buffer_offset_ << "\n " <<
  //   "bytes_read = " << bytes_read;
  // if (route_request_->status() == net::ERR_IO_PENDING) {
  //   DLOG(INFO) << "IpcURLLoader::ReadMore: url_request_->status().is_io_pending() = true. waiting for OnReadCompleted";
  //   // Wait for OnReadCompleted.
  // } else {
  //   DLOG(INFO) << "IpcURLLoader::ReadMore: url_request_->status().is_io_pending() = false"; //. calling DidRead(" << bytes_read << ")";
    
  //   // |this| may have been deleted.
  // }
}

void IpcURLLoader::OnRead(int num_bytes) {
  if (num_bytes == net::ERR_IO_PENDING) {
  } else {
    DidRead(num_bytes, false);
  }
}

void IpcURLLoader::DidRead(int num_bytes, bool completed_synchronously) {
  //DLOG(INFO) << "IpcURLLoader::DidRead: bytes = " << num_bytes;
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  if (num_bytes > 0) {
    pending_write_buffer_offset_ += num_bytes;

    // Only notify client of download progress in case DevTools are attached
    // and we're done sniffing and started sending response.
    if (report_raw_headers_ && !consumer_handle_.is_valid()) {
      int64_t total_encoded_bytes = 0;//url_request_->GetTotalReceivedBytes();
      int64_t delta = total_encoded_bytes - reported_total_encoded_bytes_;
      DCHECK_LE(0, delta);
      if (delta) {
        //DLOG(INFO) << "IpcURLLoader::DidRead: calling url_loader_client_->OnTransferSizeUpdated(delta). delta = " << delta;
        url_loader_client_->OnTransferSizeUpdated(delta);
      }
      reported_total_encoded_bytes_ = total_encoded_bytes;
    }
  }
  //if (update_body_read_before_paused_) {
  //  update_body_read_before_paused_ = false;
  //  body_read_before_paused_ = url_request_->GetRawBodyBytes();
  //}

  bool complete_read = true;
  if (consumer_handle_.is_valid()) {
    const std::string& type_hint = response_->head.mime_type;
    std::string new_type;
    bool made_final_decision = net::SniffMimeType(
        pending_write_->buffer(), 
        pending_write_buffer_offset_,
        //url_request_->url(), 
        GURL(),
        type_hint,
        net::ForceSniffFileUrlsForHtml::kDisabled, &new_type);
    // SniffMimeType() returns false if there is not enough data to determine
    // the mime type. However, even if it returns false, it returns a new type
    // that is probably better than the current one.
    response_->head.mime_type.assign(new_type);

    // Mumba: This "early" SendResponseClient were sometimes messing with
    // the IO flow on the application mojo pipe even when the data is all
    // there

    if (made_final_decision) {
      SendResponseToClient();
    } else {
      //complete_read = false;
      // FIXME: testing
      SendResponseToClient();
    }
    //DLOG(INFO) << "IpcURLLoader::DidRead: made_final_decision = " << made_final_decision <<
    // "complete_read: " << complete_read;

    //if (!made_final_decision) {
    //  complete_read = false;
    //  SendResponseToClient();
    //}
    
    
    // if (route_entry_->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM ||
    //     route_entry_->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM) {
    //   //DLOG(INFO) << "IpcURLLoader::DidRead: server or bidi stream method. sending response to client now";
    //   complete_read = true;
    //   SendResponseToClient();
    // }
  }

  if (route_request_->status() != net::OK || num_bytes == 0) {
    CompletePendingWrite();
    NotifyCompleted(route_request_->status());
    // |this| will have been deleted.
    return;
  }

  if (complete_read) {
    CompletePendingWrite();
  }

  if (completed_synchronously) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::BindOnce(&IpcURLLoader::ReadMore, weak_ptr_factory_.GetWeakPtr()));
  } else {
    ReadMore();
  }
}

void IpcURLLoader::NotifyCompleted(int error_code) {
  if (error_code == net::ERR_FAILED) {
    route_request_->CancelWithError(error_code);
  }

  if (consumer_handle_.is_valid()) {
    SendResponseToClient();
  }

  network::URLLoaderCompletionStatus status;
  status.error_code = error_code;
  status.exists_in_cache = false;//url_request_->response_info().was_cached;
  status.completion_time = base::TimeTicks::Now();
  status.encoded_data_length = route_request_->GetTotalReceivedBytes();
  status.encoded_body_length = route_request_->GetRawBodyBytes();
  status.decoded_body_length = total_written_bytes_;

  url_loader_client_->OnComplete(status);
  DeleteSelf();
  // FIXME: see if this is what we want
  //        the error was that we are reusing the same loader
  //        for more than one resource and this number get down
  //        the pipe as the received bytes and being a sum of all the resources
  //        is not really what we want
  //total_written_bytes_ = 0;
}

void IpcURLLoader::OnConnectionError() {
  task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&IpcURLLoader::NotifyCompleted, weak_ptr_factory_.GetWeakPtr(), net::ERR_FAILED));
}

void IpcURLLoader::SendResponseToClient() {
  url_loader_client_->OnReceiveResponse(response_->head, nullptr);

  net::IOBufferWithSize* metadata = nullptr;
      //url_request_->response_info().metadata.get();
  if (metadata) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(metadata->data());

    url_loader_client_->OnReceiveCachedMetadata(
        std::vector<uint8_t>(data, data + metadata->size()));
  }

  url_loader_client_->OnStartLoadingResponseBody(std::move(consumer_handle_));
  response_ = nullptr;
}

void IpcURLLoader::SetRawResponseHeaders(scoped_refptr<const net::HttpResponseHeaders> headers) {
  raw_response_headers_ = headers;
}

void IpcURLLoader::CompletePendingWrite() {
  if (pending_write_) {
    response_body_stream_ =
      pending_write_->Complete(pending_write_buffer_offset_);
  }
  total_written_bytes_ += pending_write_buffer_offset_;
  pending_write_ = nullptr;
  pending_write_buffer_offset_ = 0;
}

}