// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_CLIENT_H_
#define NET_RPC_CLIENT_RPC_CLIENT_H_

#include <memory>

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "net/rpc/rpc.h"
#include "net/rpc/client/rpc_stream.h"

namespace net {
class RpcHost;

class NET_EXPORT RpcClient {
public:
  RpcClient(RpcHost* host);
  ~RpcClient();

  std::unique_ptr<RpcStream> NewStream(const std::string& host, const std::string& port, const std::string& name, const std::string& params);

private:
  //owned by rpc host
  RpcHost* host_;
  //scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(RpcClient);
};

}

#endif