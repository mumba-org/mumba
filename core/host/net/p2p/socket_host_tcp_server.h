// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_P2P_SOCKET_HOST_TCP_SERVER_H_
#define MUMBA_HOST_NET_P2P_SOCKET_HOST_TCP_SERVER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/atomic_sequence_num.h"
#include "base/message_loop/message_loop.h"
#include "core/host/net/p2p/socket_host.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/p2p_socket_type.h"
#include "ipc/ipc_sender.h"
#include "net/base/completion_callback.h"
#include "net/socket/tcp_server_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {
class StreamSocket;
}  // namespace net

namespace host {

class CONTENT_EXPORT P2PSocketHostTcpServer : public P2PSocketHost {
 public:
  P2PSocketHostTcpServer(Delegate* delegate,
                         base::WeakPtr<IPC::Sender> message_sender,
                         int socket_id,
                         common::P2PSocketType client_type);
  ~P2PSocketHostTcpServer() override;

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
  
 private:
  friend class P2PSocketHostTcpServerTest;

  void OnError();

  void DoAccept();
  void HandleAcceptResult(int result);

  // Callback for Accept().
  void OnAccepted(int result);

  const common::P2PSocketType client_type_;
  std::unique_ptr<net::ServerSocket> socket_;
  net::IPEndPoint local_address_;

  std::unique_ptr<net::StreamSocket> accept_socket_;
  std::map<net::IPEndPoint, std::unique_ptr<net::StreamSocket>>
      accepted_sockets_;

  //base::AtomicSequenceNumber id_gen_;

  net::CompletionCallback accept_callback_;
  
  int incoming_socket_id_;

  DISALLOW_COPY_AND_ASSIGN(P2PSocketHostTcpServer);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_P2P_SOCKET_HOST_TCP_SERVER_H_
