// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_SERVER_RPC_HANDLER_H_
#define NET_RPC_SERVER_RPC_HANDLER_H_

#include "net/base/net_export.h"

namespace net {
struct RpcCallState;

class NET_EXPORT RpcHandler {
public:
  virtual ~RpcHandler() {}
  virtual void HandleCallBegin(RpcCallState* call, const std::string& method_name, const std::string& host_name) = 0;
  virtual void HandleCallStreamRead(RpcCallState* call) = 0;
  virtual void HandleCallStreamSendInitMetadata(RpcCallState* call) = 0;
  virtual void HandleCallStreamWrite(RpcCallState* call) = 0;
  virtual void HandleCallUnaryRead(RpcCallState* call) = 0;
  virtual void HandleCallEnd(RpcCallState* call) = 0;
  virtual void HandleRpcSendError(RpcCallState* call, int rc) = 0;
};

}

#endif