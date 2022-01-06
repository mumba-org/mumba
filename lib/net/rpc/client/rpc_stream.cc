// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_stream.h"

//#include "net/rpc/client/rpc_unary_call.h"
#include "net/rpc/client/rpc_stream_buffer.h"
#include "net/rpc/client/rpc_channel.h"

namespace net { 

RpcStream::RpcStream(std::unique_ptr<RpcChannel> channel, const std::string& host, const std::string& port, const std::string& name, const std::string& params):
  channel_(std::move(channel)),
  done_reading_(false),
  uuid_(base::UUID::generate()),
  host_(host),
  port_(port),
  name_(name),
  params_(params) {

}

RpcStream::~RpcStream() {
  //DLOG(INFO) << "~RpcCallBase()";
  channel_.reset();
}

bool RpcStream::DataAvailable() const {
  return 
    (done_reading_ &&
     done_reading_code_ >= 0 && 
     output_buffer()->last_bytes_copied() < output_buffer()->bytes_readed());
}

void RpcStream::OnDoneReading(int code) {
  done_reading_ = true;
  done_reading_code_ = code;
}

void RpcStream::Cancel() {} 

}