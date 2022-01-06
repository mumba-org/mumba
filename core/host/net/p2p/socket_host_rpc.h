// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_P2P_SOCKET_HOST_RPC_H_
#define MUMBA_HOST_NET_P2P_SOCKET_HOST_RPC_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/queue.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "core/host/host_thread.h"
#include "core/host/net/p2p/socket_host.h"
#include "core/shared/common/p2p_socket_type.h"
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
}

namespace host {

class CONTENT_EXPORT P2PSocketHostRpc : public P2PSocketHost,
                                        public net::RpcSocket::Delegate {
 public:
 
  P2PSocketHostRpc(P2PSocketHost::Delegate* delegate,
                   base::WeakPtr<IPC::Sender> message_sender,
                   int socket_id,
                   common::P2PSocketType type,
                   net::URLRequestContextGetter* url_context,
                   network::ProxyResolvingClientSocketFactory*
                   proxy_resolving_socket_factory,
                   scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~P2PSocketHostRpc() override;

  net::StreamSocket* socket() const;

  bool InitAccepted(net::RpcService* service,
                    const net::IPEndPoint& remote_address,
                    std::unique_ptr<net::StreamSocket> socket,
                    grpc_exec_ctx* exec_ctx, 
                    server_state* state,
                    grpc_endpoint* tcp,
                    grpc_pollset* accepting_pollset,
                    grpc_tcp_server_acceptor* acceptor);

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

  void Read();
  void DetachFromThread() override;
 
 protected:
  struct SendBuffer {
    SendBuffer();
    SendBuffer(int32_t packet_id,
               scoped_refptr<net::DrainableIOBuffer> buffer,
               const net::NetworkTrafficAnnotationTag traffic_annotation);
    SendBuffer(const SendBuffer& rhs);
    ~SendBuffer();

    int32_t rtc_packet_id;
    scoped_refptr<net::DrainableIOBuffer> buffer;
    net::MutableNetworkTrafficAnnotationTag traffic_annotation;
  };

  // Derived classes will provide the implementation.
  int ProcessInput(char* input, int input_len);
  void DoSend(
      //const net::IPEndPoint& to,
      const std::vector<char>& data,
      const rtc::PacketOptions& options,
      const net::NetworkTrafficAnnotationTag traffic_annotation);

  void WriteOrQueue(SendBuffer& send_buffer);
  void OnPacket(const std::vector<char>& data);
  void OnError();

  void OnRpcCallDestroyed(net::RpcSocket* socket, int call_id) override;
  
 private:
  friend class P2PSocketHostTcpTestBase;
  friend class P2PSocketHostTcpServerTest;
  friend class P2PSocketHostRpcServer;
  // SSL/TLS connection functions.
  void StartTls();
  void ProcessTlsSslConnectDone(int status);

  void DidCompleteRead(int result);
  void DoRead();

  void DoWrite();
  void HandleWriteResult(int result);

  // Callbacks for Connect(), Read() and Write().
  void OnConnected(int result);
  void OnRead(int result);
  void OnWritten(int result);

  // Helper method to send socket create message and start read.
  void OnOpen(net::IPEndPoint local_address, net::IPEndPoint remote_address);
  void DoSendSocketCreateMsg(net::IPEndPoint local_address, net::IPEndPoint remote_address);

  void DoHandshake(grpc_exec_ctx* exec_ctx, 
                   server_state* state,
                   grpc_endpoint* tcp,
                   grpc_pollset* accepting_pollset,
                   grpc_tcp_server_acceptor* acceptor);

  void DoReceiveRpcMessage(int call_id, int method_type);
  void DoSendRpcMessage(int call_id, int method_type, std::vector<char> data);
  void DoSendRpcMessageNow(int call_id, int method_type, std::vector<char> data);
  void DoSendRpcStatus(int call_id, int status_code);

  void ConnnectOnIOThread(const common::P2PSocketOptions& options, scoped_refptr<base::SingleThreadTaskRunner> reply_task_runner);
  void PostSendComplete(const base::TimeTicks& send_time);
  void PostError();

  common::P2PHostAndIPEndPoint remote_address_;

  //std::unique_ptr<net::StreamSocket> socket_;
  std::unique_ptr<net::RpcSocket, HostThread::DeleteOnIOThread> socket_;
  scoped_refptr<net::GrowableIOBuffer> read_buffer_;
  base::queue<SendBuffer> write_queue_;
  SendBuffer write_buffer_;

  bool write_pending_;

  bool connected_;
  common::P2PSocketType type_;
  scoped_refptr<net::URLRequestContextGetter> url_context_;
  network::ProxyResolvingClientSocketFactory* proxy_resolving_socket_factory_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::WeakPtrFactory<P2PSocketHostRpc> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(P2PSocketHostRpc);
};


}  // namespace host


#endif