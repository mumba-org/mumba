// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_channel.h"

#include "rpc/channel/channel_stack.h"
#include "rpc/surface/channel.h"

namespace net {

RpcChannel::RpcChannel(RpcTransportType type): 
  type_(type),
  channel_(nullptr), 
  opened_(false) {

}

RpcChannel::~RpcChannel() {
  //DLOG(INFO) << "~RpcChannel";
  if (opened_) {
    DestroyChannel();
  }
}

RpcChannel::State RpcChannel::state() const {
  return static_cast<RpcChannel::State>(grpc_channel_check_connectivity_state(channel_, 1));
}

bool RpcChannel::Open(const std::string& host, const std::string& port) {
  grpc_channel_args args;

  if (opened_) {
    return false;
  }
  
  host_ = host;
  port_ = port;

  memset(&args, 0, sizeof(args));

  std::string url;

  if (type_ == RpcTransportType::kIPC) {
    url = "unix://" + host_;
  } else if (type_ == RpcTransportType::kHTTP) {
    url = host_ + ":" + port_;
  }

  channel_ = grpc_insecure_channel_create(url.c_str(), &args, nullptr);

  State current_state = state();
  if (current_state != kCONNECTING && 
      current_state != kREADY && 
      current_state != kIDLE) {
    DestroyChannel();
    return false;
  }

  //grpc_endpoint* ep = grpc_transport_get_endpoint(grpc_exec_ctx* exec_ctx, grpc_transport* transport);

  opened_ = true;
  return true;
}

void RpcChannel::Close() {
  DestroyChannel();
}

void RpcChannel::DestroyChannel() {
  if (!opened_ || channel_ == nullptr) {
    return;
  }
  grpc_channel_destroy(channel_);
  channel_ = nullptr;
  opened_ = false;
}

}