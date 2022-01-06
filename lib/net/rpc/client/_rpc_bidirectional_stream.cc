// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_bidirectional_stream.h"

#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/rpc/client/rpc_stream_buffer.h"
#include "net/rpc/client/rpc_channel.h"
#include "net/base/io_buffer.h"
#include "rpc/surface/call.h"
#include "rpc/byte_buffer.h"
#include "rpc/byte_buffer_reader.h"

namespace net {

namespace {

// RpcContinuation* BuildContinuation(RpcContinuation::Delegate* delegate, bool async) {
//   RpcContinuation* continuation = nullptr;
//   if (async)
//    continuation = new RpcAsyncContinuation(delegate);
//   else 
//    continuation = new RpcBlockingContinuation(delegate);

//  return continuation;
// }

//void* tag(intptr_t i) { return (void*)i; }

// void OnResponseReceived(grpc_exec_ctx* ctx, void* arg, grpc_error* /* error */) {
//   DLOG(INFO) << "OnResponseReceived";
//   RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);
//   caller->io_task_runner()->PostTask(FROM_HERE,
//     base::BindOnce(&RpcBidirectionalStream::OnContinue, 
//       base::Unretained(caller), 
//       true, 
//       base::Unretained(caller->call())));
// }

//void OnInitialRequestSent(grpc_exec_ctx* ctx, void* arg, grpc_error*) {
//  DLOG(INFO) << "OnInitialRequestSent";
  //RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);

//}

//void OnStatusReceived(grpc_exec_ctx* ctx, void* arg, grpc_error*) {
//  DLOG(INFO) << "OnStatusReceived";
  //RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);

//}

}  

// static 
std::unique_ptr<RpcStream> RpcBidirectionalStream::Create(
  std::unique_ptr<RpcChannel> channel, 
  const std::string& host,
  const std::string& port, 
  const std::string& name,
  const std::string& params,
  const scoped_refptr<base::TaskRunner>& task_runner) {
  return std::unique_ptr<RpcStream>(new RpcBidirectionalStream(std::move(channel), host, port, name, params, task_runner));
}  

RpcBidirectionalStream::RpcBidirectionalStream(
  std::unique_ptr<RpcChannel> channel,
  const std::string& host,
  const std::string& port, 
  const std::string& name, 
  const std::string& params,
  const scoped_refptr<base::TaskRunner>& io_task_runner):
  RpcStream(std::move(channel), host, port, name, params),
  output_(nullptr),
  call_(nullptr),
  //first_call_(true),
  delegate_task_runner_(base::SequencedTaskRunnerHandle::Get()),
  io_task_runner_(io_task_runner),
  weak_factory_(this) {
  Init();
}

RpcBidirectionalStream::~RpcBidirectionalStream() {
  if (recv_message_payload_) {
    grpc_byte_buffer_destroy(recv_message_payload_);
  }
  
  grpc_metadata_array_destroy(&begin_metadata_);
  grpc_metadata_array_destroy(&end_metadata_);
  gpr_free(output_);
}

void RpcBidirectionalStream::Init() {
  grpc_metadata_array_init(&begin_metadata_);
  grpc_metadata_array_init(&end_metadata_);

  io_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &RpcBidirectionalStream::CreateContinuation, 
        base::Unretained(this)));
  //stream_writer_.SetSource(output_buffer());
}

void RpcBidirectionalStream::CreateContinuation() {
  //continuation_.reset(new RpcPluckContinuation(this));
  continuation_.reset(new RpcNextContinuation(this));
}

RpcContinuation* RpcBidirectionalStream::continuation() const { 
  return continuation_.get(); 
}

void RpcBidirectionalStream::Call(Callback cb, void* data) {
  io_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &RpcBidirectionalStream::CallImpl, 
        base::Unretained(this),
        base::Unretained(data),
        base::Passed(std::move(cb))));
}  

void RpcBidirectionalStream::CallImpl(void* data, Callback cb) {
  DLOG(INFO) << "RpcBidirectionalStream::CallImpl";
  DCHECK(continuation_);

  call_ = std::make_unique<RpcCall>();
  call_->user_data = data;
  call_->cb = std::move(cb);

  grpc_call_error rc = GRPC_CALL_OK;
  grpc_metadata meta_c[2] = {{grpc_slice_from_static_string("key1"),
                              grpc_slice_from_static_string("val1"),
                              0,
                              {{NULL, NULL, NULL, NULL}}},
                             {grpc_slice_from_static_string("key2"),
                              grpc_slice_from_static_string("val2"),
                              0,
                              {{NULL, NULL, NULL, NULL}}}};
 
  call_->host_slice = grpc_slice_from_copied_string(host().c_str());
  call_->method_slice = grpc_slice_from_copied_string(name().c_str());

  // input_buffer()->WriteString(params().empty() ? "hello echo" : params().c_str());
  FillInputBuffer(params());
  
  call_->call = grpc_channel_create_call(channel_->c_channel(), nullptr, GRPC_PROPAGATE_DEFAULTS,
                                         continuation_->c_completion_queue(), call_->method_slice,
                                         &call_->host_slice, gpr_inf_future(GPR_CLOCK_REALTIME),
                                         nullptr);
  if (!call_->call) {
    DLOG(ERROR) << "grpc_channel_create_call error";
    call_.reset();
    return;
  }

  call_->ops_count = 4;
  call_->ops[0].op = GRPC_OP_SEND_INITIAL_METADATA;
  call_->ops[0].data.send_initial_metadata.count = 2;
  call_->ops[0].data.send_initial_metadata.metadata = meta_c;
  call_->ops[0].flags = 0;
  call_->ops[0].reserved = NULL;

  call_->ops[1].op = GRPC_OP_SEND_MESSAGE;
  call_->ops[1].data.send_message.send_message = send_message_payload_;
  call_->ops[1].flags = 0;
  call_->ops[1].reserved = NULL;

  call_->ops[2].op = GRPC_OP_RECV_INITIAL_METADATA;
  call_->ops[2].data.recv_initial_metadata.recv_initial_metadata = &begin_metadata_;//&recv_initial_metadata_;
  call_->ops[2].flags = 0;
  call_->ops[2].reserved = NULL;

  call_->ops[3].op = GRPC_OP_RECV_MESSAGE;
  call_->ops[3].data.recv_message.recv_message = &recv_message_payload_;
  call_->ops[3].flags = 0;
  call_->ops[3].reserved = NULL;

  //first_call_ = false;
  
  rc = grpc_call_start_batch(call_->call, call_->ops, call_->ops_count, call_.get(), nullptr);
  
  if (rc != GRPC_CALL_OK) {
    DLOG(ERROR) << "RpcBidirectionalStream::CallImpl: error in grpc_call_start_batch";
    //result = false;
  } else {
    continuation_->Schedule();
  }
}

// void RpcBidirectionalStream::CallImpl(void* data, Callback cb) {
//   DLOG(INFO) << "RpcBidirectionalStream::CallImpl";
//   DCHECK(continuation_);

//   grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

//   GRPC_CLOSURE_INIT(&on_initial_request_sent_, OnInitialRequestSent, this,
//                     grpc_schedule_on_exec_ctx);
//   GRPC_CLOSURE_INIT(&on_response_received_, OnResponseReceived, this,
//                     grpc_schedule_on_exec_ctx);
//   GRPC_CLOSURE_INIT(&on_status_received_, OnStatusReceived, this,
//                     grpc_schedule_on_exec_ctx);
  
//   call_ = std::make_unique<RpcCall>();
//   call_->user_data = data;
//   call_->cb = std::move(cb);

//   //bool result = true;

//   grpc_call_error rc = GRPC_CALL_OK;
//   grpc_metadata meta_c[2] = {{grpc_slice_from_static_string("key1"),
//                               grpc_slice_from_static_string("val1"),
//                               0,
//                               {{NULL, NULL, NULL, NULL}}},
//                              {grpc_slice_from_static_string("key2"),
//                               grpc_slice_from_static_string("val2"),
//                               0,
//                               {{NULL, NULL, NULL, NULL}}}};
 
//   call_->host_slice = grpc_slice_from_copied_string(host().c_str());
//   call_->method_slice = grpc_slice_from_copied_string(name().c_str());

//   //input_buffer()->WriteString(params().empty() ? "hello echo" : params().c_str());

//   FillInputBuffer(params());

//   call_->call = grpc_channel_create_call(channel_, nullptr, GRPC_PROPAGATE_DEFAULTS,
//                                          continuation_->c_completion_queue(), call_->method_slice,
//                                          &call_->host_slice, gpr_inf_future(GPR_CLOCK_REALTIME),
//                                          nullptr);
//   if (!call_->call) {
//     DLOG(ERROR) << "grpc_channel_create_call error";
//     call_.reset();
//     return;//false;
//   }

//   call_->ops_count = 4;
//   call_->ops[0].op = GRPC_OP_SEND_INITIAL_METADATA;
//   call_->ops[0].data.send_initial_metadata.count = 2;
//   call_->ops[0].data.send_initial_metadata.metadata = meta_c;
//   call_->ops[0].flags = 0;
//   call_->ops[0].reserved = NULL;

//   call_->ops[1].op = GRPC_OP_SEND_MESSAGE;
//   call_->ops[1].data.send_message.send_message = send_message_payload_;
//   call_->ops[1].flags = 0;
//   call_->ops[1].reserved = NULL;

//   rc = grpc_call_start_batch_and_execute(&exec_ctx, call_->call, &call_->ops[1], 2, &on_initial_request_sent_);
//   if (rc != GRPC_CALL_OK) {
//     DLOG(ERROR) << "RpcBidirectionalStream::CallImpl: error in grpc_call_start_batch";
//   }

//   call_->ops[2].op = GRPC_OP_RECV_INITIAL_METADATA;
//   call_->ops[2].data.recv_initial_metadata.recv_initial_metadata = &begin_metadata_;//&recv_initial_metadata_;
//   call_->ops[2].flags = 0;
//   call_->ops[2].reserved = NULL;

//   call_->ops[3].op = GRPC_OP_RECV_MESSAGE;
//   //output_buffer()->BindBuffer(&call_->ops[3]);
//   call_->ops[3].data.recv_message.recv_message = &recv_message_payload_;
//   call_->ops[3].flags = 0;
//   call_->ops[3].reserved = NULL;

//   rc = grpc_call_start_batch_and_execute(&exec_ctx, call_->call, &call_->ops[2], 2, &on_response_received_);
//   if (rc != GRPC_CALL_OK) {
//     DLOG(ERROR) << "RpcBidirectionalStream::CallImpl: error in grpc_call_start_batch";
//   }

//   call_->ops[4].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
//   call_->ops[4].data.recv_status_on_client.trailing_metadata = &end_metadata_;
//   call_->ops[4].data.recv_status_on_client.status = &call_status_;
//   call_->ops[4].data.recv_status_on_client.status_details = &call_status_details_;
//   call_->ops[4].flags = 0;
//   call_->ops[4].reserved = NULL;

//   rc = grpc_call_start_batch_and_execute(
//       &exec_ctx, call_->call, &call_->ops[4], 1, &on_status_received_);

//   first_call_ = false;
 
//   grpc_exec_ctx_finish(&exec_ctx);  
// }

void RpcBidirectionalStream::SendReceivedAck(RpcCall* call) {
  DLOG(INFO) << "RpcBidirectionalStream::SendReceivedAck";
  //output_stream_.reset(new RpcStreamBuffer());
  //input_stream_.reset(new RpcStreamBuffer());

  grpc_call_error rc = GRPC_CALL_OK;
  //grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  //call_->call = grpc_channel_create_call(channel_, nullptr, GRPC_PROPAGATE_DEFAULTS,
  //                                       continuation_->c_completion_queue(), call_->method_slice,
  //                                       &call_->host_slice, gpr_inf_future(GPR_CLOCK_REALTIME),
  //                                       nullptr);

  //if (!call_->call) {
  //  DLOG(ERROR) << "grpc_channel_create_call error";
  //  return;
  //}
  
  call_->ops_count = 1;

  //call_->ops[0].op = GRPC_OP_SEND_MESSAGE;
  //call_->ops[0].data.send_message.send_message = input_buffer()->buffer_;
  //call_->ops[0].flags = 0;
  //call_->ops[0].reserved = NULL;

  //call_->ops[0].op = GRPC_OP_RECV_INITIAL_METADATA;
  //call_->ops[0].data.recv_initial_metadata.recv_initial_metadata = &output_buffer()->begin_metadata_;//&recv_initial_metadata_;
  //call_->ops[0].flags = 0;
  //call_->ops[0].reserved = NULL;

  call_->ops[0].op = GRPC_OP_RECV_MESSAGE;
  call_->ops[0].data.recv_message.recv_message = &recv_message_payload_;
  call_->ops[0].flags = 0;
  call_->ops[0].reserved = NULL;

  //ops[1].op = GRPC_OP_RECV_MESSAGE;
  //output_buffer()->BindBuffer(&ops[1]);
  //ops[1].flags = 0;
  //ops[1].reserved = NULL;

  //GRPC_CLOSURE_INIT(&on_response_received_, OnResponseReceived, this,
  //                  grpc_schedule_on_exec_ctx);
  
  //rc = grpc_call_start_batch_and_execute(&exec_ctx, call_->call, call_->ops, call_->ops_count, &on_response_received_);
  rc = grpc_call_start_batch(call_->call, call_->ops, call_->ops_count, call_.get(), nullptr);
  
  if (rc != GRPC_CALL_OK) {
    DLOG(ERROR) << "RpcBidirectionalStream::SendReceivedAck: error in grpc_call_start_batch";
    return;
  }

  //grpc_exec_ctx_finish(&exec_ctx);
}

int64_t RpcBidirectionalStream::input_length() const {
  return input_length_;
}

int64_t RpcBidirectionalStream::output_length() const {
  return output_length_;
}

int RpcBidirectionalStream::Read(IOBuffer* buf, int buf_len) const {
  DCHECK(output_);
  int readed = static_cast<int>(output_length_);
  int bytes_to_copy = readed <= buf_len ? readed : buf_len;
  memcpy(buf->data(), output_, bytes_to_copy);
  return bytes_to_copy;
}

int RpcBidirectionalStream::Read(std::string* out) const {
  DCHECK(output_);
  out->assign(output_, output_length_);
  return output_length_;
}

int RpcBidirectionalStream::Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) const {
  int readed = static_cast<int>(output_length_);
  int bytes_to_copy = readed <= buf_len ? readed : buf_len; 
  memcpy(data->front(), output_, bytes_to_copy);
  return bytes_to_copy;
}

void RpcBidirectionalStream::Shutdown() {
  weak_factory_.InvalidateWeakPtrs();
  call_.reset();
}

void RpcBidirectionalStream::OnContinue(bool ok, RpcCall* call) {
  if (ok) {
    base::WaitableEvent event{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
    //output_buffer()->set_data_available();
    // this is nasty, but we need those ops to be sequential
    // and we need to dispatch to the original delegate thread
    // giving some params(mostly mojo ptrs) needs thread locality
    // SendReceivedAck() will bind again into the output_buffer()
    // while at the same time the delegate thread might be reading it.. 
    delegate_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &RpcBidirectionalStream::ProcessReceivedData,
        base::Unretained(this),
        base::Unretained(call),
        base::Unretained(&event)));
    //DLOG(INFO) << "RpcBidirectionalStream::OnContinue: waiting for ProcessReceivedData ...";
    event.Wait();
    SendReceivedAck(call);  
    return;
  }
  delegate_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(call->cb, net::ERR_FAILED, nullptr, call->call_and_close));
}

void RpcBidirectionalStream::ProcessReceivedData(RpcCall* call, base::WaitableEvent* event) {
  FillOutputBuffer(call);
  call->cb.Run(net::OK, call->user_data, call->call_and_close);
  if (event) {
    event->Signal();
  }
}

void RpcBidirectionalStream::FillInputBuffer(const std::string& data) {
  input_length_ = data.size();
  grpc_slice buffer_slice = grpc_slice_from_copied_string(data.c_str());
  send_message_payload_ = grpc_raw_byte_buffer_create(&buffer_slice, 1);
  grpc_slice_unref(buffer_slice);
}

void RpcBidirectionalStream::FillOutputBuffer(RpcCall* call) {
  if (!recv_message_payload_) {
    output_length_ = 0;  
    call->call_and_close = true;
    OnDoneReading(ERR_FAILED);
    return;
  }
  grpc_byte_buffer_reader reader;
  grpc_byte_buffer_reader_init(&reader, recv_message_payload_);
  grpc_slice resp_slice = grpc_byte_buffer_reader_readall(&reader);
  grpc_byte_buffer_reader_destroy(&reader);
  output_length_ = GRPC_SLICE_LENGTH(resp_slice);
  output_ = grpc_slice_to_c_string(resp_slice);
  grpc_slice_unref(resp_slice);
  OnDoneReading(OK);
}

void RpcBidirectionalStream::OnTimeout() {
  if (call_->call_and_close) {
    OnContinue(false, call_.get());
  }
  //scoped_refptr<base::RefCountedBytes> output = new base::RefCountedBytes(reinterpret_cast<const unsigned char *>("hello world"), 11);
  //cb.Run(true, output, 11);
  //cb.Run(false, scoped_refptr<base::RefCountedString>(), 0);
}

void RpcBidirectionalStream::OnShutdown() {
  OnDoneReading(OK);
  Shutdown();
  //cb.Run(false, scoped_refptr<base::RefCountedString>(), 0);
}

}