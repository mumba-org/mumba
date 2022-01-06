// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_request.h"

#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/route/ipc_route_request_peer.h"
#include "core/host/route/route_dispatcher_client.h"
#include "services/network/chunked_data_pipe_upload_data_stream.h"
#include "services/network/data_pipe_element_reader.h"
#include "services/network/loader_util.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/net_adapters.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_response.h"
#include "services/network/resource_scheduler_client.h"

namespace host {

// namespace {

constexpr size_t kDefaultAllocationSize = 16 * 1024;

// }

RouteRequest::RouteRequest(int id,
                           base::WeakPtr<RouteRequestDelegate> delegate, 
                           RouteDispatcherClient* route_dispatcher_client, 
                           const GURL& url,
                           scoped_refptr<base::SequencedTaskRunner> route_task_runner): 
  id_(id),
  delegate_(std::move(delegate)),
  route_dispatcher_client_(route_dispatcher_client),
  route_dispatcher_(route_dispatcher_client_->route_dispatcher()),
  peer_(new IpcRouteRequestPeer(this)),
  state_(STATE_NONE),
  status_(net::OK),
  url_(url),
  total_sent_bytes_(0),
  total_readed_bytes_(0),
  content_lenght_(0),
  expected_content_size_(0),
  is_pending_read_(false),
  creation_time_(base::TimeTicks::Now()),
  send_handle_watcher_(FROM_HERE,
                       mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                       base::SequencedTaskRunnerHandle::Get()),
  send_handle_closed_watcher_(FROM_HERE,
                              mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                              base::SequencedTaskRunnerHandle::Get()),
  receive_handle_watcher_(FROM_HERE,
                          mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                          base::SequencedTaskRunnerHandle::Get()),
  receive_handle_closed_watcher_(FROM_HERE,
                                 mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                                 base::SequencedTaskRunnerHandle::Get()),
  main_task_runner_(base::ThreadTaskRunnerHandle::Get()),
  impl_task_runner_(route_task_runner),
  main_weak_ptr_(this),
  impl_weak_ptr_(this) {

  route_dispatcher_client_->BindPeer(peer_->GetWeakPtr());
}

RouteRequest::~RouteRequest() {
  CloseStream();
}

net::HttpResponseHeaders* RouteRequest::response_headers() const {
  return response_info_.headers.get();
}

void RouteRequest::Start() {
  route_dispatcher_client_->OnRequestCreated(id_);
  // impl_task_runner_->PostTask(
  //   FROM_HERE,
  //   base::BindOnce(&RouteRequest::StartImpl, 
  //                  impl_weak_ptr_.GetWeakPtr()));
  StartImpl();
}

void RouteRequest::StartImpl() {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  state_ = STATE_CREATE_STREAM;

  mojo::DataPipe pipe_a;
  mojo::DataPipe pipe_b;

  // create the ipc pipe stream
  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(MojoCreateDataPipeOptions);
  options.flags = MOJO_CREATE_DATA_PIPE_OPTIONS_FLAG_NONE;
  options.element_num_bytes = 1;
  options.capacity_num_bytes = kDefaultAllocationSize;
  
  // create the local reader/remote writer pair
  MojoResult result =
      mojo::CreateDataPipe(&options, &pipe_a.producer_handle, &pipe_a.consumer_handle);
  if (result != MOJO_RESULT_OK) {
    DLOG(ERROR) << "CreateDataPipe";
    OnNetworkReadCompleted(net::ERR_INSUFFICIENT_RESOURCES);
    return;
  }

  // create the local writer/remote reader pair
  result = mojo::CreateDataPipe(&options, &pipe_b.producer_handle, &pipe_b.consumer_handle);
  if (result != MOJO_RESULT_OK) {
    DLOG(ERROR) << "CreateDataPipe";
    OnNetworkReadCompleted(net::ERR_INSUFFICIENT_RESOURCES);
    return;
  }

  receive_handle_ = std::move(pipe_a.consumer_handle);
  send_handle_ = std::move(pipe_b.producer_handle);
   
  send_handle_watcher_.Watch(
    send_handle_.get(), 
    MOJO_HANDLE_SIGNAL_WRITABLE,
    base::Bind(&RouteRequest::OnStreamSendEvent,
      base::Unretained(this)));

  //send_handle_watcher_.ArmOrNotify();
  
  send_handle_closed_watcher_.Watch(
    send_handle_.get(), 
    MOJO_HANDLE_SIGNAL_PEER_CLOSED,
    base::Bind(&RouteRequest::OnStreamSendClose,
      base::Unretained(this)));

  send_handle_closed_watcher_.ArmOrNotify();
  
  receive_handle_watcher_.Watch(
    receive_handle_.get(), 
    MOJO_HANDLE_SIGNAL_READABLE,
    base::Bind(&RouteRequest::OnStreamReceiveEvent,
                base::Unretained(this)));
  
  receive_handle_watcher_.ArmOrNotify();
  
  receive_handle_closed_watcher_.Watch(
    receive_handle_.get(), 
    MOJO_HANDLE_SIGNAL_PEER_CLOSED,
    base::Bind(&RouteRequest::OnStreamReceiveClose,
                base::Unretained(this)));

  receive_handle_closed_watcher_.ArmOrNotify();
  
  
  // now send the consumer handle to the other party on the ipc line
  // that will write the data for us
  OnStreamAvailable(std::move(pipe_b.consumer_handle), std::move(pipe_a.producer_handle));
}

void RouteRequest::GetLoadTimingInfo(net::LoadTimingInfo* load_timing_info) const {
  *load_timing_info = response_info_.load_timing; 
}

void RouteRequest::GetMimeType(std::string* mime_type) const {
  mime_type->assign(response_info_.mime_type.begin(), response_info_.mime_type.end()); 
}

void RouteRequest::GetCharset(std::string* charset) const {
  *charset = response_info_.charset;
}

void RouteRequest::Read(net::IOBuffer* buf, int max_bytes, base::OnceCallback<void(int)> callback) {
  // impl_task_runner_->PostTask(
  //   FROM_HERE,
  //   base::BindOnce(&RouteRequest::ReadImpl,
  //                  impl_weak_ptr_.GetWeakPtr(),
  //                  base::Unretained(buf),
  //                  max_bytes,
  //                  base::Passed(std::move(callback))));
  ReadImpl(buf, max_bytes, std::move(callback));
}

void RouteRequest::ReadImpl(net::IOBuffer* buf, int max_bytes, base::OnceCallback<void(int)> callback) {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  int to_write = static_cast<int>(pending_read_buffer_size_) > max_bytes ? max_bytes : pending_read_buffer_size_;
  if (to_write > 0) {
    memcpy(buf->data(), pending_receive_buffer_->buffer(), to_write);
  } 
  main_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      to_write == 0 ? net::ERR_IO_PENDING : to_write));
  // check if we want to call it even in case to_write = 0
  OnNetworkReadCompleted(to_write);
}

void RouteRequest::OnRequestStarted(int request_id) {
  //DLOG(INFO) << "RouteRequest::OnRequestStarted(dispatcher client): request_id = " << request_id;
}

void RouteRequest::OnUploadProgress(int request, uint64_t position, uint64_t size) {
  //DLOG(INFO) << "RouteRequest::OnUploadProgress(dispatcher client): request = " << request;
}

bool RouteRequest::OnReceivedRedirect(
  int request, 
  const net::RedirectInfo& redirect_info, 
  const network::ResourceResponseInfo& info,
  scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  //DLOG(INFO) << "RouteRequest::OnReceivedRedirect(dispatcher client): request = " << request;
  return false;
}

void RouteRequest::OnReceivedResponse(int request, const network::ResourceResponseHead& response_head) {
  //DLOG(INFO) << "RouteRequest::OnReceivedResponse(dispatcher client): request = " << request;
  response_info_ = response_head;

  content_lenght_ = response_info_.headers->GetContentLength();
  // check if those match
  expected_content_size_ = response_info_.encoded_body_length;
}

void RouteRequest::OnStartLoadingResponseBody(int request, mojo::ScopedDataPipeConsumerHandle body) {
  
}

void RouteRequest::OnDownloadedData(int request, int len, int encoded_data_length) {
  
}

void RouteRequest::OnReceivedData(int request, std::unique_ptr<RouteRequestPeer::ReceivedData> data) {
  
}

void RouteRequest::OnTransferSizeUpdated(int request, int transfer_size_diff) {
  
}

void RouteRequest::OnReceivedCachedMetadata(int request, const std::vector<uint8_t>& data, int len) {
  
}

void RouteRequest::OnCompletedRequest(int request, const network::URLLoaderCompletionStatus& status) {
  delegate_->OnReadCompleted(this, net::OK);
}

void RouteRequest::OnStreamAvailable(mojo::ScopedDataPipeConsumerHandle send_handle, 
                                     mojo::ScopedDataPipeProducerHandle receive_handle) {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  state_ = STATE_SEND_REQUEST;
  StartRequestOnMainThread(std::move(send_handle), std::move(receive_handle));
}

void RouteRequest::StartRequestOnMainThread(mojo::ScopedDataPipeConsumerHandle send_handle, 
                                            mojo::ScopedDataPipeProducerHandle receive_handle) {
  //DCHECK(main_task_runner_->RunsTasksInCurrentSequence());
  route_dispatcher_->StartRequest(id_, url_.spec(), std::move(send_handle), std::move(receive_handle));
}

void RouteRequest::OnStreamReadDataAvailable(int bytes) {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  // if the last state was SEND_REQUEST then this is the first data arriving
  bool first_data = state_ == STATE_SEND_REQUEST;
  state_ = STATE_REPLY_RECEIVED;
  if (first_data) {
    // FIXME: much safer if we have a weak ptr of our delegate
    //        giving its lifetime and ours is not garantee to outlive
    //        the task being posted here
    main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&RouteRequestDelegate::OnResponseStarted,
                     delegate_,
                     base::Unretained(this),
                     (bytes >= 0 ? net::OK : net::ERR_FAILED)));
  } else{
    main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&RouteRequestDelegate::OnStreamReadDataAvailable, 
                    delegate_,
                    base::Unretained(this),
                    bytes));
  }
}

void RouteRequest::CancelWithError(int error_code) {
  DLOG(INFO) << "RouteRequest::CancelWithError: not implemented";
}

void RouteRequest::CloseStream() {
  state_ = STATE_CLOSE_STREAM;
  ShutdownReceive();
  ShutdownSend();
}

void RouteRequest::OnStreamReceiveEvent(MojoResult result) {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  ReadMore();
}

void RouteRequest::OnStreamSendEvent(MojoResult result) {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());  
}

void RouteRequest::OnStreamSendClose(MojoResult result) {
  
}

void RouteRequest::OnStreamReceiveClose(MojoResult result) {
  
}

void RouteRequest::ReadMore() {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  //DCHECK(receive_handle_.is_valid());
  //DCHECK(!pending_receive_buffer_);

  if (!receive_handle_.is_valid()) {
    //DCHECK(pending_receive_buffer_->IsComplete());
    receive_handle_ = pending_receive_buffer_->ReleaseHandle();
  }
  
  uint32_t num_bytes = 0;
  
  MojoResult result = network::MojoToNetPendingBuffer::BeginRead(
    &receive_handle_, &pending_receive_buffer_, &num_bytes);
  
  if (result == MOJO_RESULT_SHOULD_WAIT) {
    receive_handle_watcher_.ArmOrNotify();
    return;
  }
  
  if (result != MOJO_RESULT_OK) {
    ShutdownReceive();
    return;
  }

  pending_read_buffer_size_ = num_bytes;
  pending_read_buffer_offset_ = num_bytes;
  is_pending_read_ = true;

  OnStreamReadDataAvailable(num_bytes);
}

void RouteRequest::CompletePendingRead() {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  if (pending_receive_buffer_) {
    pending_receive_buffer_->CompleteRead(pending_read_buffer_offset_);
  } //else {
  //  DLOG(ERROR) << "warning: pending_receive_buffer_ is not here";
  //}
  total_readed_bytes_ += pending_read_buffer_offset_;
  
  // FIXME: content_lenght_ should not be like this by now
  //        and this is a hack
  if (content_lenght_ <= 0) {
    content_lenght_ = total_readed_bytes_; 
  }

  //pending_write_ = nullptr;
  pending_read_buffer_offset_ = 0;
  pending_read_buffer_size_ = 0;
  is_pending_read_ = false;

  receive_handle_watcher_.ArmOrNotify();
}

void RouteRequest::ShutdownReceive() {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  //DCHECK(receive_handle_.is_valid());
  //DCHECK(!pending_receive_buffer_);

  receive_handle_watcher_.Cancel();
  pending_receive_buffer_ = nullptr;
  receive_handle_.reset();
}

void RouteRequest::ShutdownSend() {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  //DCHECK(send_handle_.is_valid());
  //DCHECK(!pending_send_buffer_);

  send_handle_watcher_.Cancel();
  pending_send_buffer_ = nullptr;
  send_handle_.reset();
}

void RouteRequest::OnNetworkReadCompleted(int status) {
  //DCHECK(impl_task_runner_->RunsTasksInCurrentSequence());
  CompletePendingRead();
}


}