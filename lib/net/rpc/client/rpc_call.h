// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_CALL_H_
#define NET_RPC_CLIENT_RPC_CALL_H_

#include <memory>

#include "base/macros.h"
#include "base/logging.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/ref_counted_memory.h"
#include "rpc/grpc.h"
#include "net/base/net_errors.h"
#include "net/rpc/rpc.h"

namespace net {
class RpcStream;
class RpcStreamBuffer;
class RpcChannel;
class RpcContinuation;
class RpcBidirectionalStream;
class RpcUnidirectionalStream;


class NET_EXPORT RpcCall {
public:
  RpcCall(RpcStream* stream,
          RpcChannel* channel,
          RpcContinuation* continuation,
          RpcMethodType type,
          const std::string& host,
          const std::string& method);

  ~RpcCall();

  grpc_call_error status_code() const {
    return last_status_code_;
  }

  const char* status_message() const {
    return grpc_call_error_to_string(last_status_code_);
  }

  RpcStreamBuffer* input_buffer() const {
    return input_buffer_.get();
  }

  RpcStreamBuffer* output_buffer() const {
    return output_buffer_.get();
  }

  void set_output_buffer(std::unique_ptr<RpcStreamBuffer> output_buffer);

  bool call_and_close() const {
    return call_and_close_;
  }

  void set_call_and_close(bool value) {
    call_and_close_ = value;
  }

  int timeouts() const {
    return timeouts_;
  }

  void set_timeout() {
    timeouts_++;
  }

  int StartBatch();
  int StartBatchAndExecute(base::OnceCallback<void()> cb);

  void OnExecuteBatchComplete(grpc_error* error);

private:
  // FIXME: make streams use public interfaces
  // instead of going straight for ops_, meta_, etc..

  friend class RpcBidirectionalStream;
  friend class RpcUnidirectionalStream;

  RpcStream* stream_;
  grpc_op ops_[20];
  // FIXME: 2 is arbitrary
  grpc_metadata meta_[2];
  size_t ops_count_;
  // if we just call once and go away = GRPC_OP_SEND_CLOSE_FROM_CLIENT
  bool call_and_close_;
  grpc_slice host_slice_;
  grpc_slice method_slice_;
  grpc_call* call_;
  void* user_data_;
  RpcMethodType type_;
  int timeouts_;
  grpc_call_error last_status_code_;
  std::unique_ptr<RpcStreamBuffer> input_buffer_;
  std::unique_ptr<RpcStreamBuffer> output_buffer_; 
  grpc_exec_ctx exec_ctx_;
  grpc_closure on_call_;
  base::OnceCallback<void()> cb_;

  DISALLOW_COPY_AND_ASSIGN(RpcCall);
};

}

#endif