// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_CHANNEL_H_
#define NET_RPC_CLIENT_RPC_CHANNEL_H_

#include "base/macros.h"
#include "rpc/grpc.h"
#include "net/rpc/rpc.h"

namespace net {

class NET_EXPORT RpcChannel {
public:

  enum State {
    kIDLE = 0,
    kCONNECTING = 1,
    kREADY = 2,
    kTRANSIENT_FAILURE = 3,
    kSHUTDOWN = 4
  };

  RpcChannel(RpcTransportType type);
  ~RpcChannel();

  RpcTransportType type() const {
    return type_;
  }
  
  State state() const;

  bool is_open() const {
    return opened_;
  }

  const std::string& host() const {
    return host_;
  }

  const std::string& port() const {
    return port_;
  }

  grpc_channel* c_channel() const {
    return channel_;
  }

  bool Open(const std::string& host, const std::string& port);
  void Close();

private:

  void DestroyChannel();

  RpcTransportType type_;
  grpc_channel* channel_;
  std::string host_;
  std::string port_;
  bool opened_;
 
 DISALLOW_COPY_AND_ASSIGN(RpcChannel);
};

}

#endif
