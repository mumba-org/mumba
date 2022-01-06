// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_SOCKET_CLIENT_H_
#define NET_RPC_RPC_SOCKET_CLIENT_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/queue.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "net/rpc/server/rpc_socket.h"
#include "net/base/completion_callback.h"
#include "net/base/ip_endpoint.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "rpc/grpc.h"
#include "rpc/iomgr/tcp_server.h"

struct server_state;
struct grpc_tcp_listener;

namespace network {
class ProxyResolvingClientSocketFactory;
}  // namespace network

namespace net {
class DrainableIOBuffer;
class GrowableIOBuffer;
class StreamSocket;
class URLRequestContextGetter;
}  // namespace net

namespace net {
class RpcService;

class NET_EXPORT RpcSocketClient : public net::RpcSocket::Delegate {
public:
 RpcSocketClient(int id);
 ~RpcSocketClient();

 RpcSocket* socket() const {
   return socket_.get();
 }

 bool InitAccepted(RpcService* service,
                   const net::IPEndPoint& remote_address,
                   std::unique_ptr<net::StreamSocket> socket,
                   grpc_exec_ctx* exec_ctx, 
                   server_state* state,
                   grpc_endpoint* tcp,
                   grpc_pollset* accepting_pollset,
                   grpc_tcp_server_acceptor* acceptor);

 void OnRpcCallDestroyed(net::RpcSocket* socket, int call_id) override;

private:

 void DoHandshake(grpc_exec_ctx* exec_ctx, 
                  server_state* state,
                  grpc_endpoint* tcp,
                  grpc_pollset* accepting_pollset,
                  grpc_tcp_server_acceptor* acceptor);

 int id_;
 //common::P2PHostAndIPEndPoint remote_address_;
 net::IPEndPoint ip_address_;
 std::unique_ptr<RpcSocket> socket_;

 DISALLOW_COPY_AND_ASSIGN(RpcSocketClient);
};

}

#endif