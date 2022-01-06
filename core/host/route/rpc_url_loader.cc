// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/rpc_url_loader.h"

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
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
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

void PopulateResourceResponse(net::URLRequest* request,
                              bool is_load_timing_enabled,
                              bool include_ssl_info,
                              network::ResourceResponse* response) {
  response->head.request_time = request->request_time();
  response->head.response_time = request->response_time();
  response->head.headers = request->response_headers();
  request->GetCharset(&response->head.charset);
  response->head.content_length = request->GetExpectedContentSize();
  request->GetMimeType(&response->head.mime_type);
  net::HttpResponseInfo response_info = request->response_info();
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

// GURL FormatURL(const std::string& scheme, RouteEntry* node, const GURL& input_url) {
//   std::string path;
//   HostRpcService* service = node->service();
//   std::string host = service->host();
//   // this works to define to listen on any device
//   // but as a target is invalid
//   if (host == "0.0.0.0") {
//     host = "127.0.0.1";
//   }
  
//   base::ReplaceChars(node->fullname(), ".", "/", &path);
//   DLOG(INFO) << "FormatUrl: url entry fullname = '" << node->fullname() << "' input url = " << input_url.spec();
//   std::string url_string;
//   if (!input_url.query().empty()) {
//     url_string = scheme + "://" + host + ":" + base::NumberToString(service->port()) + "/" + path + "?" + input_url.query();
//   } else {
//     url_string = scheme + "://" + host + ":" + base::NumberToString(service->port()) + "/" + path;
//   }
//   return GURL(url_string);
// }

// std::string GetEntryNameFromURL(const GURL& url) {
//   std::string result = url.path();
//   size_t path_offset = result.find("//");
//   if (path_offset != std::string::npos) {
//     result = result.substr(path_offset+1);
//     path_offset = result.find("/");
//     if (path_offset != std::string::npos) {
//       result = result.substr(0, path_offset);
//     }
//   }
//   return result;
// }

std::string GetMethodTypeStringFromMethodType(common::mojom::RouteEntryRPCMethodType type) {
  switch (type) {
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_CLIENT_STREAM:
      return "CLIENT_STREAM";
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL:
    //  return "NORMAL";
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM:
      return "SERVER_STREAM";
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM:
      return "BIDIRECTIONAL";
  }
  return "NORMAL";
}


}

RpcURLLoader::RpcURLLoader(
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
    uint32_t request_id): //,
    //scoped_refptr<network::ResourceSchedulerClient> resource_scheduler_client): 
      task_runner_(task_runner),
      url_request_context_(url_request_context),
      route_registry_(registry),
      route_entry_(route_entry),
      //encoder_(encoder),
      //network_service_client_(network_service_client),
      delete_callback_(std::move(delete_callback)),
      options_(options),
      //resource_type_(request.resource_type),
      is_load_timing_enabled_(request.enable_load_timing),
      //process_id_(process_id),
      //render_frame_id_(request.render_frame_id),
      //request_id_(request_id),
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
      //resource_scheduler_client_(std::move(resource_scheduler_client)),
      weak_ptr_factory_(this) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  // GetMimeTypeFromExtension
  base::ScopedAllowBlockingForTesting allow;

  binding_.set_connection_error_handler(
    base::BindOnce(&RpcURLLoader::OnConnectionError, base::Unretained(this)));

  //std::string entry_name = GetEntryNameFromURL(request.url);

  //DLOG(INFO) << "RpcUrlLoader: looking up entry: request.url: " << request.url.spec();// << " => scheme: " << request.url.scheme() << " name: " << entry_name;
  if (!route_entry_) {
    route_entry_ = route_registry_->model()->GetEntry(request.url);
  }
  DCHECK(route_entry_);

  GURL url = route_entry_->ResolveRpcRoute(request.url);//FormatURL("rpc", url_entry_, request.url);
  url_request_ = url_request_context_->CreateRequest(
      GURL(url), request.priority, this, traffic_annotation);
  
  // we are bending the rules by using method here to mean something else
  // but this will route to the rpc pipe on the url reuest loader
  url_request_->set_method(GetMethodTypeStringFromMethodType(route_entry_->rpc_method_type()));
  url_request_->set_initiator(request.request_initiator);
  url_request_->SetLoadFlags(request.load_flags);
  
  if (report_raw_headers_) {
    url_request_->SetRequestHeadersCallback(
        base::Bind(&net::HttpRawRequestHeaders::Assign,
                   base::Unretained(&raw_request_headers_)));
    url_request_->SetResponseHeadersCallback(
        base::Bind(&RpcURLLoader::SetRawResponseHeaders, base::Unretained(this)));
  }

  std::string mime_type;
  std::string extension = request.url.spec();
  auto offset = extension.find_last_of(".");
  if (offset != std::string::npos) {
    extension = extension.substr(offset + 1);
  } else {
    extension = "html";
  }
  net::GetMimeTypeFromExtension(FILE_PATH_LITERAL(extension), &mime_type);

  net::HttpRequestHeaders headers = request.headers;
  headers.SetHeader("mime-type", mime_type);
  url_request_->SetExtraRequestHeaders(headers);
  url_request_->Start();
}

RpcURLLoader::~RpcURLLoader() {
  //DLOG(INFO) << "~RpcURLLoader";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (keepalive_) {
    return;
  }
}

void RpcURLLoader::ResumeStart() {
  //DLOG(INFO) << "RpcURLLoader::ResumeStart";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  url_request_->Start();
}

void RpcURLLoader::OnResponseStarted(net::URLRequest* url_request, int net_error) {
  //DLOG(INFO) << "RpcURLLoader::OnResponseStarted";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  DCHECK(url_request == url_request_.get());

  if (net_error != net::OK) {
    NotifyCompleted(net_error);
    // |this| may have been deleted.
    return;
  }

  // Do not account header bytes when reporting received body bytes to client.
  reported_total_encoded_bytes_ = url_request_->GetTotalReceivedBytes();

  response_ = new network::ResourceResponse();
  PopulateResourceResponse(
      url_request_.get(), is_load_timing_enabled_,
      options_ & network::mojom::kURLLoadOptionSendSSLInfoWithResponse, response_.get());
  if (report_raw_headers_) {
    response_->head.raw_request_response_info = network::BuildRawRequestResponseInfo(
        *url_request_, raw_request_headers_, raw_response_headers_.get());
    raw_request_headers_ = net::HttpRawRequestHeaders();
    raw_response_headers_ = nullptr;
  }

  //DLOG(INFO) << "RpcURLLoader::OnResponseStarted: creating response_body_stream_ from data_pipe.producer_handle";
  //mojo::DataPipe data_pipe(kDefaultAllocationSize);
 // response_body_stream_ = std::move(data_pipe.producer_handle);
 // consumer_handle_ = std::move(data_pipe.consumer_handle);
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
      base::Bind(&RpcURLLoader::OnResponseBodyStreamConsumerClosed,
                 base::Unretained(this)));
  peer_closed_handle_watcher_.ArmOrNotify();

  writable_handle_watcher_.Watch(
      response_body_stream_.get(), MOJO_HANDLE_SIGNAL_WRITABLE,
      base::Bind(&RpcURLLoader::OnResponseBodyStreamReady,
                 base::Unretained(this)));

  if (!(options_ & network::mojom::kURLLoadOptionSniffMimeType) ||
      !ShouldSniffContent(url_request_.get(), response_.get())) {
    // DLOG(INFO) << "RpcURLLoader::OnResponseStarted: SendResponseToClient()";
    SendResponseToClient();
  }

  // Start reading...
  ReadMore();
}

void RpcURLLoader::OnReadCompleted(net::URLRequest* url_request, int bytes_read) {
  //DLOG(INFO) << "RpcURLLoader::OnReadCompleted: bytes = " << bytes_read;
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  //DCHECK(url_request == url_request_.get());

  DidRead(bytes_read, false);
  // |this| may have been deleted.
}

void RpcURLLoader::OnResponseBodyStreamConsumerClosed(MojoResult result) {
  //DLOG(INFO) << "RpcURLLoader::OnResponseBodyStreamConsumerClosed";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  NotifyCompleted(net::ERR_FAILED);
}

void RpcURLLoader::OnResponseBodyStreamReady(MojoResult result) {
  //DLOG(INFO) << "RpcURLLoader::OnResponseBodyStreamReady";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  if (result != MOJO_RESULT_OK) {
    DLOG(ERROR) << "RpcURLLoader::OnResponseBodyStreamReady: error returned. calling NotifyCompleted(net::ERR_FAILED)";
    NotifyCompleted(net::ERR_FAILED);
    return;
  }

  ReadMore();
}

void RpcURLLoader::DeleteSelf() {
  std::move(delete_callback_).Run(this);
}

void RpcURLLoader::FollowRedirect() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  if (!url_request_) {
    NotifyCompleted(net::ERR_UNEXPECTED);
    // |this| may have been deleted.
    return;
  }

  url_request_->FollowDeferredRedirect();
}

void RpcURLLoader::ProceedWithResponse() {
  //DLOG(INFO) << "RpcURLLoader::ProceedWithResponse: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RpcURLLoader::SetPriority(net::RequestPriority priority,
                               int32_t intra_priority_value) {
  //DLOG(INFO) << "RpcURLLoader::SetPriority: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RpcURLLoader::PauseReadingBodyFromNet() {
  //DLOG(INFO) << "RpcURLLoader::PauseReadingBodyFromNet: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RpcURLLoader::ResumeReadingBodyFromNet() {
  //DLOG(INFO) << "RpcURLLoader::ResumeReadingBodyFromNet: NOT IMPLEMENTED";
  //NOTREACHED();
}

void RpcURLLoader::ReadMore() {
  //DLOG(INFO) << "RpcURLLoader::ReadMore";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  // Once the MIME type is sniffed, all data is sent as soon as it is read from
  // the network.
  DCHECK(consumer_handle_.is_valid() || !pending_write_);

  if (!pending_write_.get()) {
    // TODO: we should use the abstractions in MojoAsyncResourceHandler.
    DCHECK_EQ(0u, pending_write_buffer_offset_);
//DLOG(INFO) << "RpcURLLoader::ReadMore: writing pending_write_buffer_size_ = " << pending_write_buffer_size_ << " on ipc pipe";
    MojoResult result = network::NetToMojoPendingBuffer::BeginWrite(
        &response_body_stream_, &pending_write_, &pending_write_buffer_size_);
    if (result != MOJO_RESULT_OK && result != MOJO_RESULT_SHOULD_WAIT) {
      // The response body stream is in a bad state. Bail.
      //DLOG(INFO) << "RpcURLLoader::ReadMore: BeginWrite() FAILED. calling NotifyCompleted(net::ERR_FAILED)";
      NotifyCompleted(net::ERR_FAILED);
      return;
    }

    //DLOG(INFO) << "RpcURLLoader::ReadMore: pending_write_buffer_size_ after = BeginWrite() " << pending_write_buffer_size_;

    DCHECK_GT(static_cast<uint32_t>(std::numeric_limits<int>::max()),
              pending_write_buffer_size_);
    if (consumer_handle_.is_valid()) {
      DCHECK_GE(pending_write_buffer_size_,
                static_cast<uint32_t>(net::kMaxBytesToSniff));
    }
    if (result == MOJO_RESULT_SHOULD_WAIT) {
     // DLOG(INFO) << "RpcURLLoader::ReadMore: result == MOJO_RESULT_SHOULD_WAIT. writable_handle_watcher_.ArmOrNotify()";
      // The pipe is full. We need to wait for it to have more space.
      writable_handle_watcher_.ArmOrNotify();
      return;
    }
  }

  auto buf = base::MakeRefCounted<network::NetToMojoIOBuffer>(
      pending_write_.get(), pending_write_buffer_offset_);
  int bytes_read;
  url_request_->Read(buf.get(),
                     static_cast<int>(pending_write_buffer_size_ -
                                      pending_write_buffer_offset_),
                     &bytes_read);
  // DLOG(INFO) << "\n\nRpcURLLoader::ReadMore:\n pending_write_buffer_offset_ = " << 
  //   pending_write_buffer_offset_ << "\n pending_write_buffer_size_ = " << pending_write_buffer_size_ << "\n " <<
  //   "pending_write_buffer_size_ - pending_write_buffer_offset_ = " << pending_write_buffer_size_ - pending_write_buffer_offset_ << "\n " <<
  //   "bytes_read = " << bytes_read;
  if (url_request_->status().is_io_pending()) {
   // DLOG(INFO) << "RpcURLLoader::ReadMore: url_request_->status().is_io_pending() = true. waiting for OnReadCompleted";
    // Wait for OnReadCompleted.
  } else {
    //DLOG(INFO) << "RpcURLLoader::ReadMore: url_request_->status().is_io_pending() = false. calling DidRead(" << bytes_read << ")";
    DidRead(bytes_read, true);
    // |this| may have been deleted.
  }
}

void RpcURLLoader::DidRead(int num_bytes, bool completed_synchronously) {
  //DLOG(INFO) << "RpcURLLoader::DidRead: bytes = " << num_bytes;
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  if (num_bytes > 0) {
    pending_write_buffer_offset_ += num_bytes;

    // Only notify client of download progress in case DevTools are attached
    // and we're done sniffing and started sending response.
    if (report_raw_headers_ && !consumer_handle_.is_valid()) {
      int64_t total_encoded_bytes = url_request_->GetTotalReceivedBytes();
      int64_t delta = total_encoded_bytes - reported_total_encoded_bytes_;
      DCHECK_LE(0, delta);
      if (delta) {
        //DLOG(INFO) << "RpcURLLoader::DidRead: calling url_loader_client_->OnTransferSizeUpdated(delta). delta = " << delta;
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
        pending_write_->buffer(), pending_write_buffer_offset_,
        url_request_->url(), type_hint,
        net::ForceSniffFileUrlsForHtml::kDisabled, &new_type);
    // SniffMimeType() returns false if there is not enough data to determine
    // the mime type. However, even if it returns false, it returns a new type
    // that is probably better than the current one.
    response_->head.mime_type.assign(new_type);

    // Mumba: This "early" SendResponseClient were sometimes messing with
    // the IO flow on the application mojo pipe even when the data is all
    // there

    // if (made_final_decision) {
    //   DLOG(INFO) << "RpcURLLoader::DidRead: made_final_decision = true. mime_type = " << new_type << " calling SendResponseToClient()";
    //   //SendResponseToClient();
    // } else {
    //   DLOG(INFO) << "RpcURLLoader::DidRead: made_final_decision = false. complete_read = false;";
    //   complete_read = false;
    // }
    //DLOG(INFO) << "RpcURLLoader::DidRead: made_final_decision = " << made_final_decision <<
    // "complete_read: " << complete_read;

    if (!made_final_decision) {
      complete_read = false;
    }
    
    
    if (route_entry_->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM ||
        route_entry_->rpc_method_type() == common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM) {
      //DLOG(INFO) << "RpcURLLoader::DidRead: server or bidi stream method. sending response to client now";
      complete_read = true;
      SendResponseToClient();
    }
  }

  if (!url_request_->status().is_success() || num_bytes == 0) {
    //DLOG(INFO) << "RpcURLLoader::DidRead: url_request_->status().is_success() = " << url_request_->status().is_success() << ". num_bytes = " << num_bytes << " calling CompletePendingWrite() && NotifyCompleted()";
    CompletePendingWrite();
    NotifyCompleted(url_request_->status().ToNetError());
    // |this| will have been deleted.
    return;
  }

  if (complete_read) {
    //DLOG(INFO) << "RpcURLLoader::DidRead: complete_read = true. calling CompletePendingWrite()";
    CompletePendingWrite();
  }

  if (completed_synchronously) {
   // DLOG(INFO) << "RpcURLLoader::DidRead: completed_synchronously = true. calling ReadMore()";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::BindOnce(&RpcURLLoader::ReadMore, weak_ptr_factory_.GetWeakPtr()));
  } else {
   // DLOG(INFO) << "RpcURLLoader::DidRead: completed_synchronously = false. calling ReadMore()";
    ReadMore();
  }
}

void RpcURLLoader::NotifyCompleted(int error_code) {
  //DLOG(INFO) << "RpcURLLoader::NotifyCompleted: err_code = " << error_code;
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  if (error_code == net::ERR_FAILED) {
    url_request_->CancelWithError(error_code);
  }

  if (consumer_handle_.is_valid()) {
    //DLOG(INFO) << "RpcURLLoader::NotifyCompleted: consumer_handle_.is_valid() = true. calling SendResponseToClient()";
    SendResponseToClient();
  }

  network::URLLoaderCompletionStatus status;
  status.error_code = error_code;
  if (error_code == net::ERR_QUIC_PROTOCOL_ERROR) {
    net::NetErrorDetails details;
    url_request_->PopulateNetErrorDetails(&details);
    status.extended_error_code = details.quic_connection_error;
  }
  status.exists_in_cache = url_request_->response_info().was_cached;
  status.completion_time = base::TimeTicks::Now();
  status.encoded_data_length = url_request_->GetTotalReceivedBytes();
  status.encoded_body_length = url_request_->GetRawBodyBytes();
  status.decoded_body_length = total_written_bytes_;

  // DLOG(INFO) << "RpcURLLoader::NotifyCompleted: " << 
  //  "\n encoded_data_length/url_request_->GetTotalReceivedBytes(): " << url_request_->GetTotalReceivedBytes() <<
  //  "\n encoded_body_length/url_request_->GetRawBodyBytes(): " << url_request_->GetRawBodyBytes() <<
  //  "\n decoded_body_length/total_written_bytes_: " <<  total_written_bytes_;
  //DLOG(INFO) << "RpcURLLoader::NotifyCompleted: url_loader_client_->OnComplete(status)";
  url_loader_client_->OnComplete(status);
  DeleteSelf();
  // FIXME: see if this is what we want
  //        the error was that we are reusing the same loader
  //        for more than one resource and this number get down
  //        the pipe as the received bytes and being a sum of all the resources
  //        is not really what we want
  //total_written_bytes_ = 0;
}

void RpcURLLoader::OnConnectionError() {
  //DLOG(INFO) << "RpcURLLoader::OnConnectionError: calling NotifyCompleted(net::ERR_FAILED)";
  
  //NotifyCompleted(net::ERR_FAILED);
  task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&RpcURLLoader::NotifyCompleted, weak_ptr_factory_.GetWeakPtr(), net::ERR_FAILED));
}

void RpcURLLoader::SendResponseToClient() {
  //DLOG(INFO) << "RpcURLLoader::SendResponseToClient";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  //DLOG(INFO) << "RpcURLLoader::SendResponseToClient: calling url_loader_client_->OnReceiveResponse()";
  url_loader_client_->OnReceiveResponse(response_->head, nullptr);

  net::IOBufferWithSize* metadata =
      url_request_->response_info().metadata.get();
  if (metadata) {
    //DLOG(INFO) << "RpcURLLoader::SendResponseToClient: metadata! calling url_loader_client_->OnReceiveCachedMetadata()";
    const uint8_t* data = reinterpret_cast<const uint8_t*>(metadata->data());

    url_loader_client_->OnReceiveCachedMetadata(
        std::vector<uint8_t>(data, data + metadata->size()));
  }

  //DLOG(INFO) << "RpcURLLoader::SendResponseToClient: calling url_loader_client_->OnStartLoadingResponseBody()";
  url_loader_client_->OnStartLoadingResponseBody(std::move(consumer_handle_));
  response_ = nullptr;
}

void RpcURLLoader::SetRawResponseHeaders(scoped_refptr<const net::HttpResponseHeaders> headers) {
  //DLOG(INFO) << "RpcURLLoader::SetRawResponseHeaders";
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  raw_response_headers_ = headers;
}

void RpcURLLoader::CompletePendingWrite() {
  //DLOG(INFO) << "RpcURLLoader::CompletePendingWrite: pending_write_->Complete(pending_write_buffer_offset_ = " << pending_write_buffer_offset_ << ") total_written_bytes_ = " << total_written_bytes_;
  //DCHECK(task_runner_->RunsTasksInCurrentSequence());
  
  response_body_stream_ =
      pending_write_->Complete(pending_write_buffer_offset_);
  total_written_bytes_ += pending_write_buffer_offset_;
  pending_write_ = nullptr;
  pending_write_buffer_offset_ = 0;
}

}