// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_bidirectional_stream.h"

#include "base/strings/string_number_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/rpc/client/rpc_stream_buffer.h"
#include "net/rpc/client/rpc_channel.h"
#include "net/base/io_buffer.h"
#include "net/rpc/client/rpc_call.h"
#include "rpc/surface/call.h"
#include "rpc/byte_buffer.h"
#include "rpc/byte_buffer_reader.h"

namespace net {

namespace {

constexpr int kDefaultBufferSize = 16384;

// RpcContinuation* BuildContinuation(RpcContinuation::Delegate* delegate, bool async) {
//   RpcContinuation* continuation = nullptr;
//   if (async)
//    continuation = new RpcAsyncContinuation(delegate);
//   else 
//    continuation = new RpcBlockingContinuation(delegate);

//  return continuation;
// }

void* tag(intptr_t i) { return (void*)i; }

void OnResponseReceived(grpc_exec_ctx* ctx, void* arg, grpc_error* error) {
   //DLOG(INFO) << "OnResponseReceived: error = " << error;
   RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);
   //caller->io_task_runner()->PostTask(FROM_HERE,
    // caller->delegate_task_runner()->PostTask(
    //   FROM_HERE,
    //  base::BindOnce(&RpcBidirectionalStream::OnReadCompletion, 
    //    base::Unretained(caller)));
  caller->OnReadCompletion();
}

//void OnInitialRequestSent(grpc_exec_ctx* ctx, void* arg, grpc_error*) {
//  DLOG(INFO) << "OnInitialRequestSent";
  //RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);

//}

//void OnStatusReceived(grpc_exec_ctx* ctx, void* arg, grpc_error*) {
//  DLOG(INFO) << "OnStatusReceived";
  //RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);

//}

void OnCloseReceived(grpc_exec_ctx* ctx, void* arg, grpc_error* error) {
  RpcBidirectionalStream* caller = static_cast<RpcBidirectionalStream*>(arg);
  caller->OnCloseCompletion();
}

}  

// static 
std::unique_ptr<RpcStream> RpcBidirectionalStream::Create(
  std::unique_ptr<RpcChannel> channel, 
  const std::string& host,
  const std::string& port, 
  const std::string& name,
  const std::string& params,
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  RpcMethodType type) {
  return std::unique_ptr<RpcStream>(new RpcBidirectionalStream(std::move(channel), host, port, name, params, task_runner, type));
}  

RpcBidirectionalStream::RpcBidirectionalStream(
  std::unique_ptr<RpcChannel> channel,
  const std::string& host,
  const std::string& port, 
  const std::string& name, 
  const std::string& params,
  const scoped_refptr<base::SequencedTaskRunner>& io_task_runner,
  RpcMethodType type):
  RpcStream(std::move(channel), host, port, name, params),
  next_state_(kSTREAM_NONE),
  type_(type),
  //continuation_(nullptr, base::OnTaskRunnerDeleter(io_task_runner)),
  //output_(nullptr),
  pending_call_(false),
  first_call_(true),
  shutting_down_(false),
  inside_loop_(false),
  reply_async_io_(false),
  close_was_sent_(false),
  read_data_available_code_(0),
  last_bytes_readed_(-1),
  last_read_code_(-1),
  content_lenght_(0),
  buffer_size_(kDefaultBufferSize),
  buffer_count_(0),
  encoded_(1),
  encoding_("protobuf"),
  //close_cancelled_(0),
  input_buffer_(new RpcStreamBuffer(this)),
  output_buffer_(new RpcStreamBuffer(this)),
  delegate_task_runner_(base::SequencedTaskRunnerHandle::Get()),
  // loop_task_runner_(
  //   base::CreateSequencedTaskRunnerWithTraits(
  //     {base::MayBlock(), 
  //      base::WithBaseSyncPrimitives(), 
  //      base::TaskPriority::USER_BLOCKING,
  //      base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN})),
  io_task_runner_(io_task_runner),
  shutdown_event_(
      base::WaitableEvent::ResetPolicy::MANUAL, 
      base::WaitableEvent::InitialState::NOT_SIGNALED),
  loop_weak_factory_(this),
  weak_factory_(this) {
  // the only 'forbidden' type for a bidi stream
  //DCHECK(type_ != RpcMethodType::kNORMAL);
 // grpc_metadata_array_init(&begin_metadata_);
}

RpcBidirectionalStream::~RpcBidirectionalStream() {
  //DLOG(INFO) << "~RpcBidirectionalStream: " << this;
  //weak_factory_.InvalidateWeakPtrs();
  
  //io_task_runner_->DeleteSoon(FROM_HERE, continuation_.release());
  
  if (recv_message_payload_) {
    grpc_byte_buffer_destroy(recv_message_payload_);
  }

  if (send_message_payload_) {
    grpc_byte_buffer_destroy(send_message_payload_);
  }
  
  //grpc_metadata_array_destroy(&begin_metadata_);
  //grpc_metadata_array_destroy(&end_metadata_);
  //gpr_free(output_);
  //loop_task_runner_ = nullptr;
}

void RpcBidirectionalStream::Init() {
  //DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());

  //grpc_metadata_array_init(&begin_metadata_);
  //grpc_metadata_array_init(&end_metadata_);

  // io_task_runner_->PostTask(
  //     FROM_HERE, 
  //     base::BindOnce(
  //       &RpcBidirectionalStream::CreateContinuation, 
  //       base::Unretained(this),
  //       weak_factory_.GetWeakPtr()));
  
  //continuation_.reset(new RpcNextContinuation(weak_factory_.GetWeakPtr(), io_task_runner_));
  continuation_.reset(new RpcNextContinuation(io_task_runner_));
  //continuation_.reset(new RpcPluckContinuation(io_task_runner_));
  
  //io_task_runner_->PostTask(
  //    FROM_HERE, 
  //    base::BindOnce(
  //      &RpcBidirectionalStream::CreateContinuation, 
  //      base::Unretained(this),
  //      continuation_->GetWeakPtr()));
  io_task_runner_->PostTask(
       FROM_HERE, 
       base::BindOnce(
         &RpcContinuation::Schedule, 
         continuation_->GetWeakPtr(),
         weak_factory_.GetWeakPtr()));
  
  // loop_task_runner_->PostTask(
  //   FROM_HERE, 
  //   base::BindOnce(&RpcBidirectionalStream::Run,
  //     base::Unretained(this)));
  Run();
}

RpcContinuation* RpcBidirectionalStream::continuation() const { 
  return continuation_.get(); 
}

RpcStreamBuffer* RpcBidirectionalStream::input_buffer() const {
  return input_buffer_.get();
}

RpcStreamBuffer* RpcBidirectionalStream::output_buffer() const {
  return output_buffer_.get();
}

void RpcBidirectionalStream::Run() {
  //DLOG(INFO) << "RpcBidirectionalStream::Run";
  set_next_state(kSTREAM_INIT);
  ScheduleIOLoop();
}

// void RpcBidirectionalStream::SendCall() {
//   io_task_runner_->PostTask(
//       FROM_HERE, 
//       base::BindOnce(
//         &RpcBidirectionalStream::CallImpl, 
//         base::Unretained(this)));
// }  


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

int64_t RpcBidirectionalStream::input_length() const {
  //base::AutoLock lock(input_buffer_lock_);
  return input_buffer_->bytes_written();
}

int64_t RpcBidirectionalStream::output_length() const {
  //base::AutoLock lock(output_buffer_lock_);
  return output_buffer_->bytes_readed();
}

int64_t RpcBidirectionalStream::total_content_length() const {
  return content_lenght_;
}

bool RpcBidirectionalStream::is_encoded() const {
  return encoded_ == 1;
}

const std::string& RpcBidirectionalStream::encoding() const {
  return encoding_;
}

int RpcBidirectionalStream::Read(IOBuffer* buf, int buf_len) {
  //DLOG(ERROR) << "RpcBidirectionalStream::Read";
  base::AutoLock lock(output_buffer_lock_);
  last_read_code_ = OK;
  
  int to_read = output_buffer_->bytes_left() - output_buffer_->last_bytes_copied();
  back_buffer_vec_lock_.Acquire();
  bool have_back_buffer = back_buffers_.size() > 0;
  //DLOG(INFO) << "RpcBidirectionalStream::Read: output_buffer_->pending_read() = " << output_buffer_->pending_read() 
  //  << " buffer_size = " << output_buffer_->bytes_readed() << " bytes_left = " << output_buffer_->bytes_left() << " have back buffer? " << have_back_buffer;
  
  if (to_read == 0 && have_back_buffer) {
    //DLOG(INFO) << "RpcBidirectionalStream::Read: read it all and with a back buffer on the wait. switching to it";
    output_buffer_.reset();
    output_buffer_ = std::move(back_buffers_.front()); 
    back_buffers_.erase(back_buffers_.begin());
  }
  back_buffer_vec_lock_.Release();

  // if (last_buffer_size >= buffer_size_ && output_buffer_->bytes_left() == 0) {
  //   DLOG(INFO) << "RpcBidirectionalStream::Read: calling Read on a drained buffer >= buffer_size_ with bytes_left = 0. returning IO_PENDING";
  //   return ERR_IO_PENDING;
  // }

  last_bytes_readed_ = output_buffer_->Read(buf, buf_len);
  
  // FIXME: should be temporary
  // OnRead(rv);
  
  //sbool pending = rv == 0 && output_length() >= 63882;
  //DLOG(INFO) << "RpcBidirectionalStream::Read (" << this << "): output_lenght = " << output_length() << " rv = " << rv << " pending? " << pending;
  // check if there other buffers and assign it to the call
  //return (rv == 0 && last_buffer_size >= buffer_size_) ? ERR_IO_PENDING : rv;
  // FIXME REAL BAD!
  //return pending ? ERR_IO_PENDING : rv;
  last_read_code_ = last_bytes_readed_;
  //DLOG(INFO) << "RpcBidirectionalStream::Read: readed = " << last_bytes_readed_ << " have_back_buffer ? " << have_back_buffer << " first_call_ ? " << first_call_;
  if (last_bytes_readed_ == 0 && have_back_buffer && !first_call_ && output_buffer_->bytes_readed() > 0) {
     //reply_async_io_ = false;
     last_read_code_ = ERR_IO_PENDING;
  }
  
  reply_async_io_ = last_read_code_ == ERR_IO_PENDING ? true : false;

  return last_read_code_;
}

int RpcBidirectionalStream::Read(std::string* out) {
  base::AutoLock lock(output_buffer_lock_);
  int rv = output_buffer_->Read(out);
  OnRead(rv);
  return rv;
}

int RpcBidirectionalStream::Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) {
  base::AutoLock lock(output_buffer_lock_);
  int rv = output_buffer_->Read(data, buf_len);
  OnRead(rv);
  return rv;
}

void RpcBidirectionalStream::OnContinue(bool ok, RpcCall* call) {
  if (shutting_down_) {
    return;
  }
  //DCHECK(io_task_runner_->RunsTasksInCurrentSequence());
  delegate_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RpcBidirectionalStream::OnContinueImpl,
      base::Unretained(this),
      ok));
}

void RpcBidirectionalStream::OnContinueImpl(bool ok) {
  //DLOG(INFO) << "RpcBidirectionalStream::OnContinueImpl";
  if (shutting_down_) {
    return;
  }
  // io_task_runner_->PostTask(
  //      FROM_HERE, 
  //      base::BindOnce(
  //        &RpcContinuation::Schedule, 
  //        continuation_->GetWeakPtr(),
  //        weak_factory_.GetWeakPtr()));
  // if (next_call_) {
  //   DLOG(INFO) << "RpcBidirectionalStream::OnContinue(" << this << "): next_call_ will turn into call_";
  //   call_.reset();
  //   call_ = std::move(next_call_);
  //   next_call_.reset();
  // }
  //bool was_pending_call = pending_call_;
  if (ok) {
    //set_next_state(was_pending_call ? kSTREAM_READ : kSTREAM_SEND_READ_ACK);
    ScheduleIOLoop();
  } else {
    read_data_available_code_ = ERR_FAILED;
    set_next_state(kSTREAM_REPLY_READ_DATA_AVAILABLE);
    ScheduleIOLoop();
  }
}

// void RpcBidirectionalStream::FillInputBuffer(const std::string& data) {
//   input_length_ = data.size();
//   grpc_slice buffer_slice = grpc_slice_from_copied_string(data.c_str());
//   send_message_payload_ = grpc_raw_byte_buffer_create(&buffer_slice, 1);
//   grpc_slice_unref(buffer_slice);
// }

// void RpcBidirectionalStream::FillOutputBuffer(RpcCall* call) {
//   if (!recv_message_payload_) {
//     output_length_ = 0;  
//     call->call_and_close = true;
//     OnDoneReading(ERR_FAILED);
//     return;
//   }
//   grpc_byte_buffer_reader reader;
//   grpc_byte_buffer_reader_init(&reader, recv_message_payload_);
//   grpc_slice resp_slice = grpc_byte_buffer_reader_readall(&reader);
//   grpc_byte_buffer_reader_destroy(&reader);
//   output_length_ = GRPC_SLICE_LENGTH(resp_slice);
//   output_ = grpc_slice_to_c_string(resp_slice);
//   grpc_slice_unref(resp_slice);
//   OnDoneReading(OK);
// }

void RpcBidirectionalStream::OnTimeout() {
  // if (shutting_down_) {
  //   return;
  // }
  //DLOG(INFO) << "RpcBidirectionalStream::OnTimeout";
  //DCHECK(io_task_runner_->RunsTasksInCurrentSequence());
  //continuation_->ShutdownLoop();
  //if (call_->call_and_close) {
  //  OnContinue(false, call_.get());
  //}
  //scoped_refptr<base::RefCountedBytes> output = new base::RefCountedBytes(reinterpret_cast<const unsigned char *>("hello world"), 11);
  //cb.Run(true, output, 11);
  //cb.Run(false, scoped_refptr<base::RefCountedString>(), 0);
}

void RpcBidirectionalStream::OnShutdown() {
  //DLOG(INFO) << "RpcBidirectionalStream::OnShutdown";
 // DCHECK(io_task_runner_->RunsTasksInCurrentSequence());
  if (shutting_down_) {
    return;
  }
  delegate_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RpcBidirectionalStream::OnShutdownImpl,
      base::Unretained(this)));
}

void RpcBidirectionalStream::OnShutdownImpl() {
  //DLOG(INFO) << "RpcBidirectionalStream::OnShutdownImpl";
  //shutting_down_ = true;
  //next_state_ = kSTREAM_DONE;
  //ScheduleIOLoop();
  read_data_available_code_ = ERR_FAILED;
  set_next_state(kSTREAM_REPLY_READ_DATA_AVAILABLE);
  ScheduleIOLoop();
}

void RpcBidirectionalStream::Shutdown() {
  //DLOG(ERROR) << "RpcBidirectionalStream::Shutdown";
  //DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  if (shutting_down_) {
    return;
  }

  // if (!close_was_sent_) {
  //   //set_next_state(kSTREAM_SEND_CLOSE);
  //   //ScheduleIOLoop();
  //   SendClose(OK);
  //   //return;
  // }

  shutting_down_ = true;
  if (pending_call_) {
    //(INFO) << "RpcBidirectionalStream::Shutdown: OnDoneReading(ERR_FAILED)";
    OnDoneReading(ERR_FAILED);
    pending_call_ = false;
  }

  back_buffers_.clear();
  //input_buffer_.reset();
  //output_buffer_.reset();

  channel()->Close();

  //loop_weak_factory_.InvalidateWeakPtrs();
  //continuation_->ShutdownOnIO();
  continuation_->Shutdown();
  //DLOG(INFO) << "RpcBidirectionalStream::Shutdown: io_task_runner_ = nullptr";
  //io_task_runner_ = nullptr;
  //DLOG(INFO) << "RpcBidirectionalStream::Shutdown: channel_.reset()";
  channel_.reset();
  //DLOG(INFO) << "RpcBidirectionalStream::Shutdown: continuation_.reset()";
  continuation_.reset();

  call_.reset();

  io_task_runner_->PostTask(FROM_HERE, base::BindOnce(&RpcBidirectionalStream::ShutdownOnIO, weak_factory_.GetWeakPtr()));
}

void RpcBidirectionalStream::ShutdownOnIO() {
  weak_factory_.InvalidateWeakPtrs();
}

void RpcBidirectionalStream::BuildCallOps(RpcCall* call, bool first_time) {
  //DLOG(ERROR) << "RpcBidirectionalStream::BuildCallOps";
  if (first_time) {

    //DLOG(INFO) << "RpcBidirectionalStream::BuildCallOps: building first call";
    // memset(call->meta_, 0, sizeof(grpc_metadata) * 2);
    // call->meta_[0] = {grpc_slice_from_static_string("key1"),
    //                  grpc_slice_from_static_string("val1"),
    //                  0,
    //                  {{NULL, NULL, NULL, NULL}}};
    // call->meta_[1] = {grpc_slice_from_static_string("key2"),
    //                  grpc_slice_from_static_string("val2"),
    //                  0,
    //                  {{NULL, NULL, NULL, NULL}}};

    call->ops_count_ = 5;

    call->ops_[0].op = GRPC_OP_SEND_INITIAL_METADATA;
    call->ops_[0].data.send_initial_metadata.count = 0;
    call->ops_[0].data.send_initial_metadata.metadata = nullptr;//&call->meta_[0];
    call->ops_[0].flags = 0;
    call->ops_[0].reserved = NULL;

    call->ops_[1].op = GRPC_OP_SEND_MESSAGE;
    call->ops_[1].data.send_message.send_message = input_buffer_->buffer_;
    call->ops_[1].flags = 0;
    call->ops_[1].reserved = NULL;

    call->ops_[2].op = GRPC_OP_SEND_CLOSE_FROM_CLIENT;
    call->ops_[2].flags = 0;
    call->ops_[2].reserved = NULL;

    call->ops_[3].op = GRPC_OP_RECV_INITIAL_METADATA;
    call->ops_[3].data.recv_initial_metadata.recv_initial_metadata = &call_->output_buffer()->begin_metadata_;//&recv_initial_metadata_;
    call->ops_[3].flags = 0;
    call->ops_[3].reserved = NULL;

    call->ops_[4].op = GRPC_OP_RECV_MESSAGE;
    output_buffer_->BindBuffer(&call->ops_[4]);
    call->ops_[4].flags = 0;
    call->ops_[4].reserved = NULL;

    //call->ops_[5].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
    //call->ops_[5].data.recv_status_on_client.trailing_metadata = &output_buffer_->end_metadata_;
    //call->ops_[5].data.recv_status_on_client.status = &close_status_;
    //call->ops_[5].data.recv_status_on_client.status_details = &close_status_details_;
    //call->ops_[5].flags = 0;
    //call->ops_[5].reserved = NULL;
  } else {
     //(INFO) << "RpcBidirectionalStream::BuildCallOps: building subsequent calls";
  //   if (type_ == RpcMethodType::kBIDI_STREAM) {
  //     call->ops_count_ = 3;
  //     call->ops_[0].op = GRPC_OP_SEND_MESSAGE;
  //     call->ops_[0].data.send_message.send_message = call->input_buffer()->buffer_;
  //     call->ops_[0].flags = 0;
  //     call->ops_[0].reserved = NULL;

  //     call->ops_[1].op = GRPC_OP_RECV_INITIAL_METADATA;
  //     call->ops_[1].data.recv_initial_metadata.recv_initial_metadata = &call->output_buffer()->begin_metadata_;
  //     call->ops_[1].flags = 0;
  //     call->ops_[1].reserved = NULL;

  //     call->ops_[2].op = GRPC_OP_RECV_MESSAGE;
  //     call->output_buffer()->BindBuffer(&call->ops_[2]);
  //     call->ops_[2].flags = 0;
  //     call->ops_[2].reserved = NULL;
  //   } else {
      call->ops_count_ = 1;
      //call->ops_[1].op = GRPC_OP_RECV_INITIAL_METADATA;
      //call->ops_[1].data.recv_initial_metadata.recv_initial_metadata = &call->output_buffer()->begin_metadata_;
      //call->ops_[1].flags = 0;
      //call->ops_[1].reserved = NULL;

      call->ops_[0].op = GRPC_OP_RECV_MESSAGE;
      call->output_buffer()->BindBuffer(&call->ops_[0]);
      call->ops_[0].flags = 0;
      call->ops_[0].reserved = NULL;

      //call->ops_[1].op = GRPC_OP_SEND_MESSAGE;
      //call->ops_[1].data.send_message.send_message = call->input_buffer()->buffer_;
      //call->ops_[1].flags = 0;
      //call->ops_[1].reserved = NULL;
   }

  // }
}

void RpcBidirectionalStream::SendClose(int status) {
  //DLOG(ERROR) << "RpcBidirectionalStream::SendClose";
  //grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  GRPC_CLOSURE_INIT(&on_close_received_, OnCloseReceived, this,
                     grpc_schedule_on_exec_ctx);

  RpcCall* call = call_.get();
  
  call->ops_[0].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
  call->ops_[0].data.recv_status_on_client.trailing_metadata = &call->output_buffer()->end_metadata_;
  call->ops_[0].data.recv_status_on_client.status = &close_status_;
  call->ops_[0].data.recv_status_on_client.status_details = &close_status_details_;
  call->ops_[0].flags = 0;
  call->ops_[0].reserved = NULL;
  
  //call->ops_[0].op = GRPC_OP_SEND_CLOSE_FROM_CLIENT;
  //call->ops_[0].flags = 0;
  //call->ops_[0].reserved = NULL;
  
    

  //grpc_call_error rc = grpc_call_start_batch_and_execute(&exec_ctx, call_->call_, call_->ops_, 1, &on_close_received_);
  grpc_call_error rc = grpc_call_start_batch(call_->call_, call_->ops_, 1, tag(1), nullptr);
  if (rc != GRPC_CALL_OK) {
    DLOG(ERROR) << "RpcBidirectionalStream::SendClose: error in grpc_call_start_batch_and_execute: " << rc;
  }
  //grpc_exec_ctx_finish(&exec_ctx);
  close_was_sent_ = true;
}

int RpcBidirectionalStream::DoLoop() {
  inside_loop_ = true;
  int rv = ERR_IO_PENDING;
  while (rv == ERR_IO_PENDING) {
    //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: next_state_ = " << next_state();
    switch (next_state()) {
      case kSTREAM_INIT:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoInit";
        rv = DoInit();
        break;
      case kSTREAM_SEND_CALL:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoSendCall";
        rv = DoSendCall();
        break;
      case kSTREAM_SEND_READ_ACK:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoSendReadAck";
        rv = DoSendReadAck();
        break;  
      case kSTREAM_READ:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoRead";
        rv = DoRead();
        break;
      case kSTREAM_REPLY_READ_DATA_AVAILABLE:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoReplyReadDataAvailable";
        rv = DoReplyReadDataAvailable();
        break;
      case kSTREAM_SEND_CLOSE:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoSendClose";
        rv = DoSendClose();
        break;  
      case kSTREAM_DONE:
        //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: DoFinish";
        rv = DoFinish();
        break;
      case kSTREAM_NONE:
        NOTREACHED();
    }
  }
  //DLOG(INFO) << "RpcBidirectionalStream::DoLoop: end. returning rv = " << rv;
  inside_loop_ = false;
  return rv;
}

int RpcBidirectionalStream::DoInit() {
  //DLOG(INFO) << "RpcBidirectionalStream::DoInit";
  //DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  
  set_next_state(kSTREAM_SEND_CALL);
  //RunContinuationLoop();
  return ERR_IO_PENDING;
}

int RpcBidirectionalStream::DoRead() {
  base::AutoLock lock(output_buffer_lock_);
  //DLOG(INFO) << "RpcBidirectionalStream::DoRead(" << this << ")";
  if (first_call_) {
    for (size_t i = 0; i < call_->output_buffer()->begin_metadata_.count; i++) {
      char* key = grpc_slice_to_c_string(call_->output_buffer()->begin_metadata_.metadata[i].key);
      char* val = grpc_slice_to_c_string(call_->output_buffer()->begin_metadata_.metadata[i].value);
      //DLOG(INFO) << "RpcBidirectionalStream::DoRead: '" << key << "' = " << val;
      if (strcmp(key, "content-lenght") == 0) {
        base::StringToInt64(val, &content_lenght_);
      } else if (strcmp(key, "encoded") == 0) {
        base::StringToInt(val, &encoded_);
      } else if (strcmp(key, "encoding") == 0) {
        encoding_ = std::string(val);
      } else if (strcmp(key, "buffer-size") == 0) {
        base::StringToInt(val, &buffer_size_);
      } else if (strcmp(key, "buffer-count") == 0) {
        base::StringToInt(val, &buffer_count_);
      }
      gpr_free(key);
      gpr_free(val);
    }
  }

  RpcStreamBuffer* output_buffer = output_buffer_.get();
  read_data_available_code_ = output_buffer->OnDataAvailable();
  //reply_async_io_ = last_bytes_readed_ > 0 && last_read_code_ == last_bytes_readed_ ? false : true;
  //reply_async_io_ = true;
  //if (!output_buffers_.empty() && output_buffer->consumed()) {
  // if (!output_buffers_.empty()) {
  //   RpcStreamBuffer* output_buffer_tmp = output_buffers_.back().get();
  //   int read_data_available_code_tmp = output_buffer->OnDataAvailable();
  //   if (output_buffer_tmp->bytes_readed() > 0) {
  //     output_buffer = output_buffer_tmp;
  //     read_data_available_code_ = read_data_available_code_tmp;
  //     OnRead(0);
  //     DLOG(INFO) << "RpcBidirectionalStream::DoRead: usando o back buffer";
  //   }
  //   //read_data_available_code_ = output_buffer->OnDataAvailable();
  // }
  pending_call_ = false;
  set_next_state(kSTREAM_REPLY_READ_DATA_AVAILABLE);
  //DLOG(INFO) << "RpcBidirectionalStream::DoRead(" << this << "): last_bytes_readed_ = " << last_bytes_readed_ << " last_read_code_ == " << last_read_code_ << " output_buffer = " << output_buffer->bytes_readed() << " bytes. returning => " << (read_data_available_code_ >= 0 ? ERR_IO_PENDING : read_data_available_code_);
  //printf("RpcBidirectionalStream::DoRead: readed %ld bytes\n-----\n%s\n-----\n", output_buffer->bytes_readed(), output_buffer_->output_);
  //set_next_state(kSTREAM_SEND_READ_ACK);
  return read_data_available_code_ >= 0 ? ERR_IO_PENDING : read_data_available_code_;
}

int RpcBidirectionalStream::DoReplyReadDataAvailable() {
  //DLOG(INFO) << "RpcBidirectionalStream::DoReplyReadDataAvailable";
  RpcStreamBuffer* output_buffer = output_buffer_.get();
  // if (!output_buffers_.empty()) {
  //   output_buffer = output_buffers_.back().get();
  // }
  bool read_all_in_one_batch = output_buffer->bytes_readed() > 0 && output_buffer->bytes_readed() < buffer_size_;
  bool done = shutting_down_ || read_all_in_one_batch;

  // FIXME: changing this for tests
  set_next_state(done ? kSTREAM_DONE : kSTREAM_SEND_READ_ACK);
  // should be temporary.. or not
  //set_next_state(shutting_down_ || read_all_in_one_batch ?  kSTREAM_DONE : kSTREAM_SEND_CALL);
  //stream_read_data_available_.Run(read_data_available_code_);
  int code = read_all_in_one_batch || first_call_ ? OK : output_buffer->bytes_readed();

  //DLOG(INFO) << "RpcBidirectionalStream::DoReplyReadDataAvailable(" << this << "): output_buffer->bytes_readed() " << output_buffer->bytes_readed() << " read_all_in_one_batch ? " << read_all_in_one_batch << " code = " << code;
  
  // if (code > 0) {
  //   output_buffer_->OnDataAvailable();
  // }
  
  // FIXME: will switch this off for now
  //        remove if {} once done
  if (reply_async_io_ || first_call_) {
    //DLOG(INFO) << "RpcBidirectionalStream::DoReplyReadDataAvailable: reply_async_io_ = true => posting " << code << " bytes";
    delegate_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(stream_read_data_available_, 
      code));//read_data_available_code_));
  }
  
  //return first_call_ ? ERR_IO_PENDING : OK;
  
  // FIXME: A simple boolean done_reading_ that would be marked to true
  //        once we know there are nothing to read would suffice.

  //return read_all_in_one_batch ? OK : ERR_IO_PENDING;
  return ERR_IO_PENDING;
}

int RpcBidirectionalStream::DoSendReadAck() {
  //DLOG(INFO) << "RpcBidirectionalStream::DoSendReadAck(" << this << ")";
  // should be temporary.. or not
  //DCHECK(false);
  
  //next_state_ = kSTREAM_SEND_CALL;
  //next_state_ = kSTREAM_REPLY_READ_DATA_AVAILABLE;

  if (first_call_) {
    OnReadCompletion();
    first_call_ = false;
  }

  // was
  set_next_state(kSTREAM_READ);
  // now is 
  // set_next_state(kSTREAM_SEND_CALL);
  
  // next_call_ = CreateCall();
  // if (!next_call_) {
  //   return ERR_FAILED;
  // }
  std::unique_ptr<RpcStreamBuffer> back_buffer = std::make_unique<RpcStreamBuffer>(this);

  //next_call_->input_buffer()->Write(params().empty() ? "_TICK_" : params());

  //next_call_->ops_[0].op = GRPC_OP_SEND_MESSAGE;
  //next_call_->ops_[0].data.send_message.send_message = next_call_->input_buffer()->buffer_;
  //next_call_->ops_[0].flags = 0;
  //next_call_->ops_[0].reserved = NULL;

  //next_call_->ops_[1].op = GRPC_OP_RECV_MESSAGE;
  //next_call_->output_buffer()->BindBuffer(&next_call_->ops_[1]);
  //next_call_->ops_[1].flags = 0;
  //next_call_->ops_[1].reserved = NULL;

  //if (first_call_) {
    // call_->ops_count_ = 1;
    // call_->ops_[0].op = GRPC_OP_RECV_MESSAGE;
    // output_buffer->BindBuffer(&call_->ops_[0]);
    // call_->ops_[0].flags = 0;
    // call_->ops_[0].reserved = NULL;
  //} else {
  //  call_->ops_count_ = 3;
  //  call_->ops_[0].op = GRPC_OP_RECV_INITIAL_METADATA;
  //  call_->ops_[0].data.recv_initial_metadata.recv_initial_metadata = &output_buffer->begin_metadata_;//&recv_initial_metadata_;
  //  call_->ops_[0].flags = 0;
  //  call_->ops_[0].reserved = NULL;

  //  call_->ops_[1].op = GRPC_OP_RECV_MESSAGE;
  //  output_buffer->BindBuffer(&call_->ops_[1]);
  //  call_->ops_[1].flags = 0;
  //  call_->ops_[1].reserved = NULL;

    //call_->ops_[2].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
    //call_->ops_[2].flags = 0;
    //call_->ops_[2].reserved = NULL;
  //}

  //ops[1].op = GRPC_OP_RECV_MESSAGE;
  //output_buffer()->BindBuffer(&ops[1]);
  //ops[1].flags = 0;
  //ops[1].reserved = NULL;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  GRPC_CLOSURE_INIT(&on_response_received_, OnResponseReceived, this,
                    grpc_schedule_on_exec_ctx);

  RpcCall* call = call_.get();

  //memset(call->meta_, 0, sizeof(grpc_metadata) * 2);
  //call->meta_[0] = {grpc_slice_from_static_string("key1"),
  //                  grpc_slice_from_static_string("val1"),
  //                  0,
  //                  {{NULL, NULL, NULL, NULL}}};
  //call->meta_[1] = {grpc_slice_from_static_string("key2"),
  //                  grpc_slice_from_static_string("val2"),
  //                  0,
  //                  {{NULL, NULL, NULL, NULL}}};

  call->ops_count_ = 1;
  // call->ops_[0].op = GRPC_OP_SEND_INITIAL_METADATA;
  // call->ops_[0].data.send_initial_metadata.count = 2;
  // call->ops_[0].data.send_initial_metadata.metadata = &call->meta_[0];
  // call->ops_[0].flags = 0;
  // call->ops_[0].reserved = NULL;

  // call->ops_[0].op = GRPC_OP_SEND_MESSAGE;
  // call->ops_[0].data.send_message.send_message = input_buffer_->buffer_;
  // call->ops_[0].flags = 0;
  // call->ops_[0].reserved = NULL;

  //call->ops_[1].op = GRPC_OP_SEND_CLOSE_FROM_CLIENT;
  //call->ops_[1].flags = 0;
  //call->ops_[1].reserved = NULL;

  //call->ops_[0].op = GRPC_OP_RECV_INITIAL_METADATA;
  //call->ops_[0].data.recv_initial_metadata.recv_initial_metadata = &output_buffer->begin_metadata_;
 // call->ops_[0].flags = 0;
 // call->ops_[0].reserved = NULL;

  call->ops_[0].op = GRPC_OP_RECV_MESSAGE;
  back_buffer->BindBuffer(&call->ops_[0]);
  call->ops_[0].flags = 0;
  call->ops_[0].reserved = NULL;

  //call->ops_[1].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
  //call->ops_[1].flags = 0;
  //call->ops_[1].reserved = NULL;

  bool is_last_read_batch = output_buffer_->bytes_readed() > 0 && output_buffer_->bytes_readed() < buffer_size_;

  if (is_last_read_batch) {
    call->ops_count_ = 2;
    call->ops_[1].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
    call->ops_[1].data.recv_status_on_client.trailing_metadata = &output_buffer_->end_metadata_;
    call->ops_[1].data.recv_status_on_client.status = &close_status_;
    call->ops_[1].data.recv_status_on_client.status_details = &close_status_details_;
    call->ops_[1].flags = 0;
    call->ops_[1].reserved = NULL;
  }

  back_buffer_vec_lock_.Acquire();
  back_buffers_.push_back(std::move(back_buffer));
  back_buffer_vec_lock_.Release();

  grpc_call_error rc = grpc_call_start_batch_and_execute(&exec_ctx, call_->call_, call_->ops_, call_->ops_count_, &on_response_received_);
  //int rc = call->StartBatch();
  //int rc = call->StartBatchAndExecute(base::BindOnce(&RpcBidirectionalStream::OnReadCompletion, base::Unretained(this)));
  if (rc != GRPC_CALL_OK) {
    //DLOG(ERROR) << "RpcBidirectionalStream::DoSendReadAck: error in grpc_call_start_batch: " << call->status_message();
    return ERR_FAILED;
  }
  
  pending_call_ = true;
  grpc_exec_ctx_finish(&exec_ctx);
  //return ERR_IO_PENDING;
  return OK;
}

// int RpcBidirectionalStream::DoSendReadAck() {
//   set_next_state(kSTREAM_READ);
//   DLOG(INFO) << "RpcBidirectionalStream::DoSendReadAck(" << this << ") : next_state = " << next_state();
//   grpc_call_error rc = GRPC_CALL_OK;
//   int ops_count = 1;//first_call_ ? 4 : 3;
//   grpc_op ops[ops_count];

//   RpcCall* call = call_.get();

//   if (recv_message_payload_) {
//     grpc_byte_buffer_destroy(recv_message_payload_);
//   }

//   //if (send_message_payload_) {
//   //  grpc_byte_buffer_destroy(send_message_payload_);
//   //}

//   grpc_metadata_array_init(&begin_metadata_);

//   //grpc_slice message = grpc_slice_from_static_string("_200_OK_");
//   //send_message_payload_ = grpc_raw_byte_buffer_create(&message, 1);

//   //if (first_call_) {
//     // ops[0].op = GRPC_OP_SEND_MESSAGE;
//     // ops[0].data.send_message.send_message = send_message_payload_;
//     // ops[0].flags = 0;
//     // ops[0].reserved = NULL;

//      //ops[0].op = GRPC_OP_RECV_INITIAL_METADATA;
//      //ops[0].data.recv_initial_metadata.recv_initial_metadata = &begin_metadata_;
//      //ops[0].flags = 0;
//      //ops[0].reserved = NULL;

//      ops[0].op = GRPC_OP_RECV_MESSAGE;
//      call->output_buffer()->BindBuffer(&ops[0]);
//      //ops[0].data.recv_message.recv_message = &recv_message_payload_;
//      ops[0].flags = 0;
//      ops[0].reserved = NULL;

//     // ops[1].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
//     // ops[1].flags = 0;
//     // ops[1].reserved = NULL;
//   if (first_call_) {
//      first_call_ = false;
//   }
//   //  } else {
//   //    ops[0].op = GRPC_OP_SEND_MESSAGE;
//   //    ops[0].data.send_message.send_message = send_message_payload_;
//   //    ops[0].flags = 0;
//   //    ops[0].reserved = NULL;

//   //    ops[1].op = GRPC_OP_RECV_INITIAL_METADATA;
//   //    ops[1].data.recv_initial_metadata.recv_initial_metadata = &begin_metadata_;
//   //    ops[1].flags = 0;
//   //    ops[1].reserved = NULL;

//   //    ops[2].op = GRPC_OP_RECV_MESSAGE;
//   //    ops[2].data.recv_message.recv_message = &recv_message_payload_;
//   //    ops[2].flags = 0;
//   //    ops[2].reserved = NULL;
//   //  }

  
//   rc = grpc_call_start_batch(call->call_, ops, ops_count, call, nullptr);
//   if (rc != GRPC_CALL_OK) {
//     DLOG(ERROR) << "RpcBidirectionalStream::DoSendReadAck: error in grpc_call_start_batch: " << grpc_call_error_to_string(rc);
//     return ERR_FAILED;
//   }
//   return OK;
// }

int RpcBidirectionalStream::DoSendCall() {
  //DLOG(INFO) << "RpcBidirectionalStream::DoSendCall";
  //set_next_state(kSTREAM_SEND_READ_ACK);
  set_next_state(kSTREAM_READ);

  DCHECK(continuation_);
  
  call_ = CreateCall();
  if (!call_) {
    //DLOG(ERROR) << "grpc_channel_create_call error";
    return ERR_FAILED;
  }

  //if (first_call_)
  input_buffer_->Write(params().empty() ? "_" : params());

  BuildCallOps(call_.get(), first_call_);

  //first_call_ = false;
  
  // FIXME: use weak pointers
  int rc = call_->StartBatch();
    //base::BindOnce(&RpcBidirectionalStream::OnReadCompletion, base::Unretained(this))
  //);
  if (rc != OK) {
    //DLOG(ERROR) << "RpcBidirectionalStream::CallImpl: error in grpc_call_start_batch";
    return ERR_FAILED;
    //result = false;
  } 
  pending_call_ = true;
    // io_task_runner_->PostTask(
    //   FROM_HERE, 
    //   base::BindOnce(
    //     &RpcContinuation::Schedule, 
    //     continuation_->GetWeakPtr()));
    //continuation_->Schedule();
  return OK;
}

int RpcBidirectionalStream::DoSendClose() {
  set_next_state(kSTREAM_DONE);
  SendClose(OK);
  // bail out of loop until we get the completion
  return ERR_IO_PENDING;
}

int RpcBidirectionalStream::DoFinish() {
  //DLOG(INFO) << "RpcBidirectionalStream::DoFinish";
  if (pending_call_) {
    //DLOG(INFO) << "RpcBidirectionalStream::DoFinish: OnDoneReading(OK)";
    OnDoneReading(OK);
    pending_call_ = false;
  }
  //SendClose(OK);
  Shutdown();
  return OK;
}

void RpcBidirectionalStream::ScheduleIOLoop() {
  //DLOG(INFO) << "RpcBidirectionalStream::ScheduleIOLoop";
  // if (delegate_task_runner_->RunsTasksInCurrentSequence()) {
  DoLoop();
  // } else {
  //delegate_task_runner_->PostTask(
  //    FROM_HERE,
  //    base::BindOnce(base::IgnoreResult(&RpcBidirectionalStream::DoLoop),
  //    loop_weak_factory_.GetWeakPtr()));
  //}
}

std::unique_ptr<RpcCall> RpcBidirectionalStream::CreateCall() {
  std::unique_ptr<RpcCall> call = std::make_unique<RpcCall>(
    this,
    channel(),
    continuation_.get(),
    type_,
    host(),
    name());
  return call;
}

void RpcBidirectionalStream::OnRead(int rv) {
  // fixme: should be temporary
  //if (rv == 0 && !output_buffers_.empty()) {
  // if (!output_buffers_.empty()) {
  //   DLOG(INFO) << "RpcBidirectionalStream::OnRead: trocando o output buffer";
  //   std::unique_ptr<RpcStreamBuffer> buffer = std::move(output_buffers_.back());
  //   output_buffer_.reset();
  //   output_buffer_ = std::move(buffer);
  //   output_buffers_.pop_back();
  //   output_buffer_->OnDataAvailable();
  // }
}

void RpcBidirectionalStream::OnReadCompletion() {
  //DLOG(INFO) << "RpcBidirectionalStream::OnReadCompletion";
  back_buffer_vec_lock_.Acquire();
  if (back_buffers_.size() > 0) {
    //DLOG(INFO) << "RpcBidirectionalStream::OnReadCompletion: back buffer count = " << back_buffers_.size();
    // if the buffer is null. theres nothing to read so dont switch to it
    // and leave the last one alone
    if (back_buffers_.begin()->get()->buffer_ != nullptr) {
      back_buffers_.begin()->get()->OnDataAvailable();
    } else {
      //DLOG(INFO) << "RpcBidirectionalStream::OnReadCompletion: back buffer on the heap is null. not stacking it";
    }
  }
  back_buffer_vec_lock_.Release();
  // size_t count = output_buffer_->buffer_->data.raw.slice_buffer.count;
  // for (size_t i = 0; i < count; ++i) {
  //   grpc_slice slice = grpc_slice_buffer_take_first(&output_buffer_->buffer_->data.raw.slice_buffer);
  //   printf("  slice - %lu bytes\n", GRPC_SLICE_LENGTH(slice));
  // }
  // grpc_byte_buffer_reader reader;  
  // grpc_byte_buffer_reader_init(&reader, output_buffer_->buffer_);
  // grpc_slice resp_slice = grpc_byte_buffer_reader_readall(&reader);
  // grpc_byte_buffer_reader_destroy(&reader);

  // int bytes_readed = GRPC_SLICE_LENGTH(resp_slice);
  // // TODO: see if in this case we can go straight to the 
  // // bytes on the slice, given this gives us a copy we dont actually need
  // // ( the insert() later will copy the data into its own memory)
  // if (bytes_readed > 0) {
  //   char* output = grpc_slice_to_c_string(resp_slice);
  //   printf("\n%d bytes\n%s\n", bytes_readed, output);
  //   gpr_free(output);
  // }

  if (!first_call_) { //&& bytes_readed > 0) {
    set_next_state(kSTREAM_READ);
    delegate_task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&RpcBidirectionalStream::OnContinueImpl, 
        base::Unretained(this),
        true));
  }
}


void RpcBidirectionalStream::OnCloseCompletion() {
  set_next_state(kSTREAM_DONE);
  delegate_task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&RpcBidirectionalStream::OnContinueImpl, 
        base::Unretained(this),
        true));
}

}