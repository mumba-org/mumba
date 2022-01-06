// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_SERVER_IPC_HANDLER_H_
#define MUMBA_HOST_RPC_SERVER_IPC_HANDLER_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread.h"
#include "base/strings/string_number_conversions.h"
#include "base/memory/ref_counted.h"
#include "net/rpc/rpc.h"
#include "ipc/ipc_sender.h"
#include "net/rpc/server/rpc_handler.h"
#include "net/rpc/server/rpc_socket.h"

namespace host {

class IPCRPCHandler : public net::RpcHandler {
public:
  IPCRPCHandler(const base::WeakPtr<IPC::Sender>& message_sender, scoped_refptr<base::SingleThreadTaskRunner> io_task_runner);
  ~IPCRPCHandler() override;

  void HandleCallBegin(net::RpcCallState* call, const std::string& method_name, const std::string& host_name) override;
  void HandleCallStreamRead(net::RpcCallState* call) override;
  void HandleCallStreamSendInitMetadata(net::RpcCallState* call) override;
  void HandleCallStreamWrite(net::RpcCallState* call) override;
  void HandleCallUnaryRead(net::RpcCallState* call) override;
  void HandleCallEnd(net::RpcCallState* call) override;
  void HandleRpcSendError(net::RpcCallState* call, int rc) override;

  
private:
  class Context;

  void DisconnectSocketOnIOThread(net::RpcSocket* socket);

  scoped_refptr<Context> context_;

  DISALLOW_COPY_AND_ASSIGN(IPCRPCHandler);
};

}

#endif