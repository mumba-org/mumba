// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kit/cpp/launcher/rpc_client.h"

#include "base/strings/string_number_conversions.h"
#include "rpc/byte_buffer_reader.h"

void* tag(intptr_t i) { return (void*)i; } 

gpr_timespec grpc_timeout_milliseconds_to_deadline(int64_t time_ms) {
   return gpr_time_add(
       gpr_now(GPR_CLOCK_MONOTONIC),
       gpr_time_from_micros((int64_t)1e3 * time_ms,
                            GPR_TIMESPAN));
}

static gpr_timespec ms_from_now(int ms) {
  return grpc_timeout_milliseconds_to_deadline(ms);
}

static void drain_cq(grpc_completion_queue* cq) {
   grpc_event ev;
   do {
     ev = grpc_completion_queue_pluck(cq, tag(1), ms_from_now(1000), nullptr);
   } while (ev.type != GRPC_QUEUE_SHUTDOWN);
}

RPCUnaryCall::RPCUnaryCall(const std::string& host, int port, const std::string& method_name): 
  host_(host),
  port_(port),
  method_name_(method_name),
  error_(false) {

  completion_queue_ = grpc_completion_queue_create_for_pluck(nullptr);

  if (!completion_queue_) {
    printf("completion queue creation error\n");
    error_ = true;
    return;
  }

}

RPCUnaryCall::~RPCUnaryCall() {
  DLOG(INFO) << "~RPCUnaryCall"; 
  //drain_cq(completion_queue);
  if (output_data_) {
    free(output_data_);
  }
  if (output_buffer_) {
    grpc_byte_buffer_destroy(output_buffer_);
  }
  if (completion_queue_) {
    grpc_completion_queue_shutdown(completion_queue_);
    grpc_completion_queue_destroy(completion_queue_);
  }
}

void RPCUnaryCall::Call(const base::CommandLine::StringVector& args, const std::string& encoded_data, int milliseconds) {
  grpc_call_error rc = GRPC_CALL_OK;
  grpc_event event;
  grpc_metadata_array begin_metadata;
  grpc_metadata_array end_metadata;
  grpc_status_code status;
  grpc_slice status_details;
  
  grpc_metadata_array_init(&begin_metadata);
  grpc_metadata_array_init(&end_metadata);

  std::string port_string = base::IntToString(port_);
  std::string full_address = host_ + ":" + port_string;

  grpc_slice host_slice = grpc_slice_from_static_string(full_address.c_str());
  grpc_slice method_slice = grpc_slice_from_static_string(method_name_.c_str());
  
  grpc_slice input_buffer_slice = grpc_slice_from_copied_buffer(encoded_data.data(), encoded_data.size());
  grpc_byte_buffer* input_buffer = grpc_raw_byte_buffer_create(&input_buffer_slice, 1);

  grpc_metadata meta_c[2] = {{grpc_slice_from_static_string("key1"),
                              grpc_slice_from_static_string("val1"),
                              0,
                              {{NULL, NULL, NULL, NULL}}},
                             {grpc_slice_from_static_string("key2"),
                              grpc_slice_from_static_string("val2"),
                              0,
                              {{NULL, NULL, NULL, NULL}}}};


  grpc_channel* channel = grpc_insecure_channel_create(full_address.c_str(), nullptr, nullptr);
  if (!channel) {
    printf("channel creation error\n");
    error_ = true;
    return;
  }
 
  grpc_call* call = grpc_channel_create_call(
    channel, 
    nullptr, 
    GRPC_PROPAGATE_DEFAULTS,
    completion_queue_, 
    method_slice,
    &host_slice, 
    gpr_inf_future(GPR_CLOCK_REALTIME), 
    nullptr);

  if (!call) {
    printf("call creation error\n");
    return;
  }

  grpc_op ops[6];
  memset(ops, 0, sizeof(ops));
  ops[0].op = GRPC_OP_SEND_INITIAL_METADATA;
  ops[0].data.send_initial_metadata.count = 2;
  ops[0].data.send_initial_metadata.metadata = meta_c;
  ops[0].flags = 0;
  ops[0].reserved = NULL;

  ops[1].op = GRPC_OP_SEND_MESSAGE;
  ops[1].data.send_message.send_message = input_buffer;
  ops[1].flags = 0;
  ops[1].reserved = NULL;

  ops[2].op = GRPC_OP_SEND_CLOSE_FROM_CLIENT;
  ops[2].flags = 0;
  ops[2].reserved = NULL;

  ops[3].op = GRPC_OP_RECV_INITIAL_METADATA;
  ops[3].data.recv_initial_metadata.recv_initial_metadata = &begin_metadata;
  ops[3].flags = 0;
  ops[3].reserved = NULL;

  ops[4].op = GRPC_OP_RECV_MESSAGE;
  ops[4].data.recv_message.recv_message = &output_buffer_;
  ops[4].flags = 0;
  ops[4].reserved = NULL;

  ops[5].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
  ops[5].data.recv_status_on_client.trailing_metadata = &end_metadata;
  ops[5].data.recv_status_on_client.status = &status;
  ops[5].data.recv_status_on_client.status_details = &status_details;
  ops[5].flags = 0;
  ops[5].reserved = NULL;

  rc = grpc_call_start_batch(call, ops, sizeof(ops) / sizeof(ops[0]), tag(1), nullptr);
  
  if (rc != GRPC_CALL_OK) {
    printf("error in grpc_call_start_batch\n");
    return;
    //goto end;
  }

  event = grpc_completion_queue_pluck(completion_queue_, tag(1), grpc_timeout_milliseconds_to_deadline(milliseconds), nullptr);

  switch (event.type) {
    case GRPC_OP_COMPLETE:
      //printf("event: complete -> %d\n", event.success);
      break;
    case GRPC_QUEUE_SHUTDOWN:
      //printf("event: shutdown\n");
      break;
    case GRPC_QUEUE_TIMEOUT:
      //printf("timeout\n");
      break;
  }

//end:
  //grpc_slice_unref(input_buffer_slice);
  //grpc_byte_buffer_destroy(input_buffer);
  //grpc_slice_unref(host_slice);
  //grpc_slice_unref(method_slice);
  //grpc_metadata_array_destroy(&begin_metadata);
  //grpc_metadata_array_destroy(&end_metadata);
  //if (channel) {
    //grpc_channel_destroy(channel);
  //}
}

void RPCUnaryCall::ReadOutputBuffer() {
  if (output_buffer_) {
    grpc_byte_buffer_reader reader;
    grpc_byte_buffer_reader_init(&reader, output_buffer_);
    grpc_slice output_slice = grpc_byte_buffer_reader_readall(&reader);
    grpc_byte_buffer_reader_destroy(&reader);
    output_data_size_ = GRPC_SLICE_LENGTH(output_slice);
    if (output_data_size_ > 0) {
      output_data_ = grpc_slice_to_c_string(output_slice);
    }
  }
}


RPCClient::RPCClient(const std::string& host, int port):
 host_(host),
 port_(port) {
  
 grpc_init();
}

RPCClient::~RPCClient() {
  grpc_shutdown();
}

std::unique_ptr<RPCUnaryCall> RPCClient::CreateRPCUnaryCall(const std::string& method_name) {
  return std::make_unique<RPCUnaryCall>(host_, port_, method_name);
}