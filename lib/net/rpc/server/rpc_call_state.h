// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_SERVER_RPC_CALL_STATE_H_
#define NET_RPC_SERVER_RPC_CALL_STATE_H_

#include "base/macros.h"
#include <memory>
#include "base/memory/ref_counted.h"
#include "rpc/grpc.h"
#include "base/uuid.h"
#include "net/rpc/server/rpc_state.h"
#include "net/rpc/rpc.h"
#include "net/rpc/rpc_service_method.h"

namespace net {
class RpcSocket;

void drain_cq(grpc_completion_queue* cq);
//void* tag(intptr_t i);
//gpr_timespec timeout_seconds_to_deadline(int64_t time_s);

struct NET_EXPORT CallStatus {
  gpr_refcount pending_ops;
  uint32_t flags;
};

struct NET_EXPORT RpcCallState {
  RpcServiceMethod* method;
  int id;
  grpc_server* server;
  grpc_call* call; 
  grpc_completion_queue* completion_queue;

  grpc_call_details* call_details;

  grpc_metadata_array send_initial_metadata;
  grpc_metadata_array recv_initial_metadata;
  grpc_metadata_array trailing_metadata;

  grpc_byte_buffer* send_message;
  grpc_byte_buffer* recv_message;

  grpc_op read_op;
  grpc_op metadata_send_op;
  grpc_op metadata_recv_op;
  grpc_op write_op;
  grpc_op status_op[2];
  grpc_op unary_ops[6];

  int cancelled;
  int timeout_count;

  RpcState state;

  int socket_id;
  RpcSocket* socket;

  grpc_closure server_on_send_message;
  grpc_closure server_on_recv_initial_metadata;
  grpc_closure server_on_recv_message;
  grpc_exec_ctx exec_ctx;

  bool is_new;
  RpcState last_type = kCALL_NOOP;
  bool done;
  bool close_stream;
  bool status_was_sent;
  bool header_readed;
  uint32_t content_size;
  uint32_t buffer_size;
  uint32_t encoded;
  uint32_t piece_count;
  std::string encoding;
  //grpc_slice slices[128];
  //int slice_count;
  grpc_metadata send_header[3];
  grpc_byte_buffer* output_buffer;
  std::string last_method;
  base::WeakPtrFactory<RpcCallState> weak_factory;

  RpcCallState();
  ~RpcCallState();

  base::WeakPtr<RpcCallState> GetWeakPtr() {
    return weak_factory.GetWeakPtr();
  }

  void Dispose() {
    if (recv_initial_metadata.metadata != nullptr) {
      grpc_metadata_array_destroy(&recv_initial_metadata);
    }
    if (send_initial_metadata.metadata != nullptr) {
      grpc_metadata_array_destroy(&send_initial_metadata);
    }

    if (send_message != nullptr) {
      grpc_byte_buffer_destroy(send_message);
    }
    if (recv_message != nullptr) {
      grpc_byte_buffer_destroy(recv_message);
    }

    grpc_completion_queue_shutdown(completion_queue);
    drain_cq(completion_queue);
    grpc_completion_queue_destroy(completion_queue);

    if (call != nullptr) {
      grpc_call_unref(call);
    }

    delete call_details;
  }

};

}

#endif