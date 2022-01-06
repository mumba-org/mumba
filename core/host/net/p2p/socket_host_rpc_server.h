// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_P2P_SOCKET_HOST_RPC_SERVER_H_
#define MUMBA_HOST_NET_P2P_SOCKET_HOST_RPC_SERVER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/atomic_sequence_num.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/waitable_event.h"
#include "core/host/net/p2p/socket_host.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/p2p_socket_type.h"
#include "ipc/ipc_sender.h"
#include "net/base/completion_callback.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_server_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "rpc/grpc.h"
#include "rpc/iomgr/tcp_server.h"

struct server_state;
struct grpc_tcp_listener;

namespace net {
class StreamSocket;
class RpcService;
}  // namespace net


namespace host {
class P2PSocketHostRpc;

class CONTENT_EXPORT P2PSocketHostRpcServer : public P2PSocketHost {
 public:
  P2PSocketHostRpcServer(Delegate* delegate,
                         base::WeakPtr<IPC::Sender> message_sender,
                         int socket_id,
                         common::P2PSocketType client_type);
  ~P2PSocketHostRpcServer() override;

  // P2PSocketHost overrides.
  bool Init(const common::P2PSocketOptions& options) override;
  void Send(const net::IPEndPoint& to,
            const std::vector<char>& data,
            const rtc::PacketOptions& options,
            uint64_t packet_id,
            const net::NetworkTrafficAnnotationTag traffic_annotation) override;
  std::unique_ptr<P2PSocketHost> AcceptIncomingTcpConnection(
      const net::IPEndPoint& remote_address) override;
  bool SetOption(common::P2PSocketOption option, int value) override;
  void ReceiveRpcMessage(int call_id, int method_type) override;
  void SendRpcMessage(int call_id, int method_type, std::vector<char> data) override;
  void SendRpcMessageNow(int call_id, int method_type, std::vector<char> data) override;
  void SendRpcStatus(int call_id, int status_code) override;
  
  const common::P2PSocketType& client_type() const {
    return client_type_;
  }
                
  void OnAccept(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err, int fd, grpc_resolved_address addr);

 private:
  
  void OnError();

  void HandleAcceptResult(int result);

  //void DoAccept();

  void OnRpcServiceStarted(
    const common::P2PHostAndIPEndPoint& remote_address,
    int result, 
    net::SocketDescriptor server_fd);

  void SendIncomingTcpConnectionOnIO(net::IPEndPoint address, int next_socket_id);
  
  // Callback for Accept().

  const common::P2PSocketType client_type_;
  net::RpcService* rpc_service_;
  net::IPEndPoint local_address_;

  std::unique_ptr<net::ServerSocket> socket_;
  std::unique_ptr<net::StreamSocket> accept_socket_;
  std::unique_ptr<P2PSocketHostRpc> socket_host_;
  //std::map<net::IPEndPoint, std::unique_ptr<net::StreamSocket>>
  //    accepted_sockets_;

//  net::CompletionCallback accept_callback_;
  //std::unique_ptr<net::StreamSocket> accept_socket_;
  //std::map<net::IPEndPoint, std::unique_ptr<net::StreamSocket>>
  //    accepted_sockets_;

  //net::CompletionCallback accept_callback_;
  //base::AtomicSequenceNumber id_gen_;
  //int next_socket_id_;
  //bool first_time_;

  scoped_refptr<base::SingleThreadTaskRunner> acceptor_thread_;

  grpc_exec_ctx* exec_ctx_;
  grpc_tcp_listener* listener_;

  bool service_started_;

  base::WaitableEvent wait_service_start_before_accept_;

  DISALLOW_COPY_AND_ASSIGN(P2PSocketHostRpcServer);
};

}  // namespace host

#endif  // MUMBA_HOST_NET_P2P_SOCKET_HOST_RPC_SERVER_H_
