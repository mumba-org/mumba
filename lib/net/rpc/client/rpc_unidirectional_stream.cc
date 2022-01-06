// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_unidirectional_stream.h"

#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/task_scheduler/post_task.h"
#include "rpc/support/alloc.h"
#include "rpc/byte_buffer.h"
#include "net/base/io_buffer.h"
#include "net/rpc/client/rpc_call.h"
#include "rpc/byte_buffer_reader.h"
#include "net/rpc/client/rpc_stream_buffer.h"
#include "net/rpc/client/rpc_channel.h"

namespace net {

// static 
std::unique_ptr<RpcStream> RpcUnidirectionalStream::Create(std::unique_ptr<RpcChannel> channel, const std::string& host, const std::string& port,  const std::string& name, const std::string& params, const scoped_refptr<base::SequencedTaskRunner>& task_runner) {
  return std::unique_ptr<RpcStream>(new RpcUnidirectionalStream(std::move(channel), host, port, name, params, task_runner));
}

RpcUnidirectionalStream::RpcUnidirectionalStream(
  std::unique_ptr<RpcChannel> channel, 
  const std::string& host,
  const std::string& port, 
  const std::string& name, 
  const std::string& params,
  const scoped_refptr<base::SequencedTaskRunner>& task_runner): 
    RpcStream(std::move(channel), host, port, name, params),
    next_state_(kSTREAM_NONE),
    pending_call_(false),
    shutting_down_(false),
    read_data_available_code_(0),
    content_lenght_(0),
    encoded_(1),
    encoding_("protobuf"),
    inside_loop_(false),
    call_(nullptr),
    //continuation_(nullptr, base::OnTaskRunnerDeleter(task_runner)),
    delegate_task_runner_(base::ThreadTaskRunnerHandle::Get()),
    // loop_task_runner_(
    // base::CreateSequencedTaskRunnerWithTraits(
    //   {base::MayBlock(), 
    //    base::WithBaseSyncPrimitives(), 
    //    base::TaskPriority::USER_BLOCKING,
    //    base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN})),
    io_task_runner_(task_runner),
    shutdown_event_(
      base::WaitableEvent::ResetPolicy::MANUAL, 
      base::WaitableEvent::InitialState::NOT_SIGNALED),
    loop_weak_factory_(this),
    weak_factory_(this) {
  //Init();
}

RpcUnidirectionalStream::~RpcUnidirectionalStream() {
  //DLOG(INFO) << "RpcUnidirectionalStream::~RpcUnidirectionalStream";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  //io_task_runner_->DeleteSoon(FROM_HERE, continuation_.release());
  //weak_factory_.InvalidateWeakPtrs();
  continuation_.reset();
  io_task_runner_ = nullptr;
  //loop_task_runner_ = nullptr;
}

RpcContinuation* RpcUnidirectionalStream::continuation() const { 
  return continuation_.get(); 
}

void RpcUnidirectionalStream::Init() {
  //DLOG(INFO) << "RpcUnidirectionalStream::Init";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  //  io_task_runner_->PostTask(
  //      FROM_HERE, 
  //      base::BindOnce(
  //        &RpcUnidirectionalStream::CreateContinuation, 
  //        base::Unretained(this),
  //        weak_factory_.GetWeakPtr()));
  
  //continuation_.reset(new RpcNextContinuation(weak_factory_.GetWeakPtr(), io_task_runner_));
  continuation_.reset(new RpcNextContinuation(io_task_runner_));
  
  // io_task_runner_->PostTask(
  //     FROM_HERE, 
  //     base::BindOnce(
  //       &RpcUnidirectionalStream::CreateContinuation, 
  //       base::Unretained(this),
  //       continuation_->GetWeakPtr()));
  io_task_runner_->PostTask(
       FROM_HERE, 
       base::BindOnce(
         &RpcContinuation::Schedule, 
         continuation_->GetWeakPtr(),
         weak_factory_.GetWeakPtr()));
  
  // loop_task_runner_->PostTask(
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &RpcUnidirectionalStream::Run,
  //     base::Unretained(this)));
  Run();
}

void RpcUnidirectionalStream::Run() {
  //DLOG(INFO) << "RpcUnidirectionalStream::Run";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  next_state_ = kSTREAM_INIT;
  ScheduleIOLoop();
}

// void RpcUnidirectionalStream::Call(Callback cb, void* data) {
//   io_task_runner_->PostTask(
//       FROM_HERE, 
//       base::BindOnce(
//         &RpcUnidirectionalStream::CallUnary,
//         base::Unretained(this),
//         host(), 
//         name(), 
//         base::Unretained(data),
//         base::Passed(std::move(cb))));
// }

// void RpcUnidirectionalStream::CallUnary(const std::string& host, const std::string& method, void* data, Callback cb) { 
  
// }

int64_t RpcUnidirectionalStream::output_length() const {
  return call_ ? call_->output_buffer()->bytes_readed() : 0;
}

int64_t RpcUnidirectionalStream::input_length() const {
  return call_ ? call_->input_buffer()->bytes_written() : 0;
}

int64_t RpcUnidirectionalStream::total_content_length() const {
  return content_lenght_;
}

bool RpcUnidirectionalStream::is_encoded() const {
  return encoded_ == 1;
}

const std::string& RpcUnidirectionalStream::encoding() const {
  return encoding_;
}

RpcStreamBuffer* RpcUnidirectionalStream::input_buffer() const {
  DCHECK(call_);
  return call_->input_buffer();
}

RpcStreamBuffer* RpcUnidirectionalStream::output_buffer() const {
  DCHECK(call_);
  return call_->output_buffer();
}

int RpcUnidirectionalStream::Read(IOBuffer* buf, int buf_len) {
  return call_->output_buffer()->Read(buf, buf_len);
}

int RpcUnidirectionalStream::Read(std::string* out) {
  return call_->output_buffer()->Read(out); 
}

int RpcUnidirectionalStream::Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) {
  return call_->output_buffer()->Read(data, buf_len);
}

void RpcUnidirectionalStream::OnContinue(bool ok, RpcCall* call) {
  //DLOG(INFO) << "RpcUnidirectionalStream::OnContinue";
  if (shutting_down_) {
    return;
  }
  DCHECK(io_task_runner_->RunsTasksInCurrentSequence());
  delegate_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RpcUnidirectionalStream::OnContinueImpl,
      base::Unretained(this),
      ok));
}

void RpcUnidirectionalStream::OnContinueImpl(bool ok) {
  //DLOG(INFO) << "RpcUnidirectionalStream::OnContinue";
  if (shutting_down_) {
    return;
  }
  // io_task_runner_->PostTask(
  //      FROM_HERE, 
  //      base::BindOnce(
  //        &RpcContinuation::Schedule, 
  //        continuation_->GetWeakPtr(),
  //        weak_factory_.GetWeakPtr()));
  pending_call_ = false;
  if (ok) {
    //DLOG(INFO) << "RpcUnidirectionalStream::OnContinue: ok. scheduling loop for kSTREAM_READ";
    next_state_ = kSTREAM_READ;
    ScheduleIOLoop();
  } else {
    //DLOG(INFO) << "RpcUnidirectionalStream::OnContinue: failed. scheduling loop for kSTREAM_REPLY_READ_DATA_AVAILABLE";
    read_data_available_code_ = ERR_FAILED;
    next_state_ = kSTREAM_REPLY_READ_DATA_AVAILABLE;
    ScheduleIOLoop();
  }
}

void RpcUnidirectionalStream::OnTimeout() {
  if (shutting_down_) {
    return;
  }
  //DLOG(INFO) << "RpcUnidirectionalStream::OnTimeout: timeouts = " << timeout_counter_ + 1;
  
  DCHECK(io_task_runner_->RunsTasksInCurrentSequence());
  continuation_->ShutdownLoop();
  // if (call_->call_and_close) {
  //   OnContinue(false, call_.get());
  // }
  // if (done_event_)
  //   done_event_->Signal();
  //cb.Run(false, scoped_refptr<base::RefCountedString>(), 0);
}

void RpcUnidirectionalStream::Shutdown() {
  //DLOG(INFO) << "RpcUnidirectionalStream::Shutdown";
  shutting_down_ = true;
  
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  loop_weak_factory_.InvalidateWeakPtrs();
  continuation_->Shutdown();
}

void RpcUnidirectionalStream::OnShutdown() {
  DCHECK(io_task_runner_->RunsTasksInCurrentSequence());
  if (shutting_down_) {
    return;
  }
  delegate_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RpcUnidirectionalStream::OnShutdownImpl,
      base::Unretained(this)));
}

void RpcUnidirectionalStream::OnShutdownImpl() {
  //DLOG(INFO) << "RpcUnidirectionalStream::OnShutdown";
  shutting_down_ = true;
  //next_state_ = kSTREAM_DONE;
  //ScheduleIOLoop();
  read_data_available_code_ = ERR_FAILED;
  next_state_ = kSTREAM_REPLY_READ_DATA_AVAILABLE;
  ScheduleIOLoop();
}

int RpcUnidirectionalStream::DoLoop() {
  //DLOG(INFO) << "RpcUnidirectionalStream::DoLoop";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  inside_loop_ = true;
  int rv = ERR_IO_PENDING;
  while (rv == ERR_IO_PENDING) {
    switch (next_state_) {
      case kSTREAM_INIT:
     //   DLOG(INFO) << "RpcUnidirectionalStream::DoLoop: DoInit";
        rv = DoInit();
        break;
      case kSTREAM_SEND_CALL:
    //    DLOG(INFO) << "RpcUnidirectionalStream::DoLoop: DoSendCall";
        rv = DoSendCall();
        break;
      case kSTREAM_READ:
    //    DLOG(INFO) << "RpcUnidirectionalStream::DoLoop: DoRead";
        rv = DoRead();
        break;
      case kSTREAM_REPLY_READ_DATA_AVAILABLE:
     //   DLOG(INFO) << "RpcUnidirectionalStream::DoLoop: DoReplyReadDataAvailable";
        rv = DoReplyReadDataAvailable();
        break;
      case kSTREAM_DONE:
       // DLOG(INFO) << "RpcUnidirectionalStream::DoLoop: DoFinish";
        rv = DoFinish();
        break;
      case kSTREAM_NONE:
        NOTREACHED();
    }
  }
  inside_loop_ = false;
  //DLOG(INFO) << "RpcUnidirectionalStream::DoLoop: returning " << rv;
  return rv;
}

int RpcUnidirectionalStream::DoInit() {
  //DLOG(INFO) << "RpcUnidirectionalStream::DoInit";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  next_state_ = kSTREAM_SEND_CALL;
  //RunContinuationLoop();
  return ERR_IO_PENDING;
}

int RpcUnidirectionalStream::DoSendCall() {
  //DLOG(INFO) << "RpcUnidirectionalStream::DoSendCall";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  
  next_state_ = kSTREAM_READ;

  call_ = CreateCall();
  
  if (!call_) {
    DLOG(ERROR) << "grpc_channel_create_call error";
    return ERR_FAILED;
  }

  call_->input_buffer()->Write(params().empty() ? "hello echo" : params());
  call_->set_call_and_close(true);

  BuildOps(call_.get());

  int rc = call_->StartBatch();
  if (rc != OK) {
    DLOG(ERROR) << "error in grpc_call_start_batch";
    call_.reset();
    return rc;
  } //else {
    // pending_call_ = true;
    // io_task_runner_->PostTask(
    //   FROM_HERE, 
    //   base::BindOnce(
    //     &RpcContinuation::Schedule, 
    //     continuation_->GetWeakPtr()));
    //continuation_->Schedule();
  //}
  pending_call_ = true;
  return rc;
}

int RpcUnidirectionalStream::DoRead() {
  //DLOG(INFO) << "RpcUnidirectionalStream::DoRead";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  next_state_ = kSTREAM_REPLY_READ_DATA_AVAILABLE;
  for (size_t i = 0; i < call_->output_buffer()->begin_metadata_.count; i++) {
    char* key = grpc_slice_to_c_string(call_->output_buffer()->begin_metadata_.metadata[i].key);
    char* val = grpc_slice_to_c_string(call_->output_buffer()->begin_metadata_.metadata[i].value);
    DLOG(INFO) << "RpcUnidirectionalStream::DoRead: '" << key << "' = " << val;
    if (strcmp(key, "content-lenght") == 0) {
      base::StringToInt64(val, &content_lenght_);
      DLOG(INFO) << "RpcUnidirectionalStream::DoRead: content_lenght = " << content_lenght_;
    }
    gpr_free(key);
    gpr_free(val);
  }
  read_data_available_code_ = call_->output_buffer()->OnDataAvailable();
  return read_data_available_code_ == 0 ? ERR_IO_PENDING : read_data_available_code_;
}

int RpcUnidirectionalStream::DoReplyReadDataAvailable() {
 // DLOG(INFO) << "RpcUnidirectionalStream::DoReplyReadDataAvailable";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  next_state_ = kSTREAM_DONE;
  delegate_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(stream_read_data_available_, 
    read_data_available_code_));
  //stream_read_data_available_.Run(read_data_available_code_);
  if (read_data_available_code_ == ERR_FAILED &&
      call_ && 
      call_->call_and_close()) {
    call_.reset();
  }
  return shutting_down_ ? ERR_IO_PENDING : OK;
}

int RpcUnidirectionalStream::DoFinish() {
  //DLOG(INFO) << "RpcUnidirectionalStream::DoFinish";
  DCHECK(delegate_task_runner_->RunsTasksInCurrentSequence());
  if (pending_call_) {
 //   DLOG(INFO) << "RpcBidirectionalStream::DoFinish: OnDoneReading(OK)";
    OnDoneReading(OK);
  }
  // if a Shutdown() were called
  // than the continuation might end its loop
  // and call delegate_->OnShutdown()
  // in this case we protect here from reentrancy
  // and possible stack overflow
  // When the OnShutdown was called by ending the loop
  // than shutting_down will be false
  if (!shutting_down_) {
    Shutdown();
  }
  return OK;
}

void RpcUnidirectionalStream::ScheduleIOLoop() {
  //DLOG(INFO) << "RpcUnidirectionalStream::ScheduleIOLoop";
  DCHECK(!inside_loop_);
  delegate_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(base::IgnoreResult(&RpcUnidirectionalStream::DoLoop),
    //weak_factory_.GetWeakPtr()));
    loop_weak_factory_.GetWeakPtr()));
}

std::unique_ptr<RpcCall> RpcUnidirectionalStream::CreateCall() {
  std::unique_ptr<RpcCall> call = std::make_unique<RpcCall>(
    this,
    channel(),
    continuation_.get(),
    RpcMethodType::kNORMAL,
    host(),
    name());
  return call;
}

void RpcUnidirectionalStream::BuildOps(RpcCall* call) {
  memset(call->meta_, 0, sizeof(grpc_metadata) * 2);

  call->meta_[0] = {grpc_slice_from_static_string("key1"),
                   grpc_slice_from_static_string("val1"),
                   0,
                   {{NULL, NULL, NULL, NULL}}};
  call->meta_[1] = {grpc_slice_from_static_string("key2"),
                   grpc_slice_from_static_string("val2"),
                   0,
                   {{NULL, NULL, NULL, NULL}}};

  call->ops_count_ = 6;
  
  call->ops_[0].op = GRPC_OP_SEND_INITIAL_METADATA;
  call->ops_[0].data.send_initial_metadata.count = 2;
  call->ops_[0].data.send_initial_metadata.metadata = &call->meta_[0];
  call->ops_[0].flags = 0;
  call->ops_[0].reserved = NULL;

  call->ops_[1].op = GRPC_OP_SEND_MESSAGE;
  call->ops_[1].data.send_message.send_message = call->input_buffer()->buffer_;
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
  //call->ops[4].data.recv_message.recv_message = &output_buffer()->buffer_;
  call->output_buffer()->BindBuffer(&call->ops_[4]);
  call->ops_[4].flags = 0;
  call->ops_[4].reserved = NULL;

  call->ops_[5].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
  call->ops_[5].data.recv_status_on_client.trailing_metadata = &call->output_buffer()->end_metadata_;
  call->ops_[5].data.recv_status_on_client.status = &status_;
  call->ops_[5].data.recv_status_on_client.status_details = &status_details_;
  call->ops_[5].flags = 0;
  call->ops_[5].reserved = NULL;
}


}