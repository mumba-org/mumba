// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_call.h"

#include "net/rpc/client/rpc_channel.h"
#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_stream_buffer.h"
#include "net/rpc/client/rpc_continuation.h"
#include "rpc/surface/call.h"
#include "rpc/iomgr/closure.h"

namespace net {

namespace {
void RpcCallOnExecuteBatch(grpc_exec_ctx* ctx, void* call, grpc_error* error) {
  RpcCall* call_state = reinterpret_cast<RpcCall*>(call);
  call_state->OnExecuteBatchComplete(error);
}

}

RpcCall::RpcCall(
  RpcStream* stream, 
  RpcChannel* channel,
  RpcContinuation* continuation,
  RpcMethodType type,
  const std::string& host,
  const std::string& method):
 stream_(stream),
 ops_count_(0),
 call_and_close_(false),
 call_(nullptr),
 user_data_(nullptr),
 type_(type),
 timeouts_(0),
 last_status_code_(GRPC_CALL_OK),
 input_buffer_(new RpcStreamBuffer(stream)),
 output_buffer_(new RpcStreamBuffer(stream)) {
  exec_ctx_ = GRPC_EXEC_CTX_INIT;
  memset(ops_, 0, sizeof(grpc_op) * 20);
  host_slice_ = grpc_slice_from_copied_string(host.c_str());
  method_slice_ = grpc_slice_from_copied_string(method.c_str());
  call_ = grpc_channel_create_call(channel->c_channel(), nullptr, GRPC_PROPAGATE_DEFAULTS,
                                   continuation->c_completion_queue(), method_slice_,
                                  &host_slice_, gpr_inf_future(GPR_CLOCK_REALTIME),
                                  nullptr);
  //char* peer = grpc_call_get_peer(call_);
  //DLOG(INFO) << "\n ** RpcCall: " << peer << " ** \n";
  //gpr_free(peer);
}

RpcCall::~RpcCall() {
  input_buffer_.reset();
  output_buffer_.reset();
  grpc_slice_unref(method_slice_);
  grpc_slice_unref(host_slice_);
  if (call_ != nullptr) {
      grpc_call_unref(call_);
  }
  grpc_exec_ctx_finish(&exec_ctx_);
}

void RpcCall::set_output_buffer(std::unique_ptr<RpcStreamBuffer> output_buffer) {
  output_buffer_.reset();
  output_buffer_ = std::move(output_buffer);
}

int RpcCall::StartBatch() {
  last_status_code_ = grpc_call_start_batch(
    call_, 
    ops_, 
    ops_count_, 
    this, 
    nullptr);
  if (last_status_code_ != GRPC_CALL_OK) {
    //DLOG(ERROR) << "error in grpc_call_start_batch";
    return ERR_FAILED;
  }
  return OK;
}

int RpcCall::StartBatchAndExecute(base::OnceCallback<void()> cb) {
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

  cb_ = std::move(cb);

  GRPC_CLOSURE_INIT(&on_call_,
                    RpcCallOnExecuteBatch, 
                    this,
                    grpc_schedule_on_exec_ctx);

  last_status_code_ = grpc_call_start_batch_and_execute(
    &exec_ctx,
    call_, 
    ops_, 
    ops_count_, 
    &on_call_);

  if (last_status_code_ != GRPC_CALL_OK) {
    return ERR_FAILED;
  }
  return OK;
}

void RpcCall::OnExecuteBatchComplete(grpc_error* error) {
  std::move(cb_).Run();
}

}