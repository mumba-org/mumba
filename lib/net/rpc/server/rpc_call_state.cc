// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/server/rpc_call_state.h"

#include "net/rpc/server/rpc_service.h"
#include "net/rpc/server/rpc_state.h"

namespace net {

void* tag(intptr_t i) { return (void*)i; }

gpr_timespec timeout_milliseconds_to_deadline(int64_t time_ms) {
  return gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_micros((int64_t)1e3 * time_ms,
                           GPR_TIMESPAN));
}

gpr_timespec timeout_seconds_to_deadline(int64_t time_s) {
  return gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_millis((int64_t)1e3 * time_s,
                           GPR_TIMESPAN));
}

gpr_timespec ms_from_now(int ms) {
  return timeout_milliseconds_to_deadline(ms);
}  

void drain_cq(grpc_completion_queue* cq) {
  grpc_event ev;
  do {
    ev = grpc_completion_queue_next(cq, ms_from_now(5000), nullptr);
  } while (ev.type != GRPC_QUEUE_SHUTDOWN);
}


RpcCallState::RpcCallState(): 
    method(nullptr),
    id(-1),
    server(nullptr),
    call(nullptr),
    completion_queue(nullptr),
    call_details(new grpc_call_details),
    send_message(nullptr),
    recv_message(nullptr),
    cancelled(0),
    timeout_count(0),
    state(RpcState::kCALL_BEGIN),
    socket_id(-1),
    socket(nullptr),
    is_new(true),
    done(false),
    close_stream(false),
    status_was_sent(false),
    header_readed(false),
    content_size(0),
    buffer_size(0),
    encoded(1),
    piece_count(0),
    encoding("protobuf"),
    weak_factory(this) {
      memset(unary_ops, 0, sizeof(grpc_op) * 6);
      memset(status_op, 0, sizeof(grpc_op) * 2);
      memset(&write_op, 0, sizeof(grpc_op));
      memset(&metadata_send_op, 0, sizeof(grpc_op));
      memset(&read_op, 0, sizeof(grpc_op));
      memset(&send_initial_metadata, 0, sizeof(grpc_metadata_array));
      memset(&recv_initial_metadata, 0, sizeof(grpc_metadata_array));
      memset(&trailing_metadata, 0, sizeof(grpc_metadata_array));
      memset(&send_header[0], 0, sizeof(grpc_metadata) * 3);
      grpc_metadata_array_init(&send_initial_metadata);
      grpc_metadata_array_init(&recv_initial_metadata);
      grpc_metadata_array_init(&trailing_metadata);
      completion_queue = grpc_completion_queue_create_for_next(nullptr);
      grpc_call_details_init(call_details);
      exec_ctx = GRPC_EXEC_CTX_INIT;
      //slice_count = 0;
      output_buffer = nullptr;
}

RpcCallState::~RpcCallState() {
  if (output_buffer) {
    grpc_byte_buffer_destroy(output_buffer);
  }
  //grpc_metadata_array_destroy(&send_initial_metadata);
  //grpc_metadata_array_destroy(&recv_initial_metadata);
  //grpc_metadata_array_destroy(&trailing_metadata);
}

}