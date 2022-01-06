// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_NET_HELPER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_NET_HELPER_H_

#include <map>

#include "core/shared/domain/net/socket_client.h"
#include "core/shared/domain/net/socket_client_delegate.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "base/single_thread_task_runner.h"
#include "NetCallbacks.h"

namespace domain {
class P2PSocketDispatcher;  
}

struct IPCSocketShim;
// TODO: We need to also support a way were
//  the shell pass the socket handle to 
//  shell process to deal with.. 
//  so instead of using IPC we do read/write/close
//  directly on the socket

class IPCSocket : public domain::P2PSocketClient {
public:
  IPCSocket(domain::P2PSocketDispatcher* dispatcher,
            SocketCallbacks callbacks,
            void* state);

  void Init(common::P2PSocketType type,
            const net::IPEndPoint& local_address,
            uint16_t min_port,
            uint16_t max_port,
            const common::P2PHostAndIPEndPoint& remote_address);

  void Init(common::P2PSocketType type,
            const net::IPEndPoint& local_address,
            uint16_t min_port,
            uint16_t max_port,
            const common::P2PHostAndIPEndPoint& remote_address,
            const std::string& package,
            const std::string& name);
  
  uint64_t Send(const net::IPEndPoint& address,
                const std::vector<char>& data,
                const rtc::PacketOptions& options) override;

  void SetOption(common::P2PSocketOption option, int value) override;

  // Must be called before the socket is destroyed.
  void Close() override;

  int GetSocketID() const override;
  void SetDelegate(domain::P2PSocketClientDelegate* delegate) override;
  void OnSocketCreated(const net::IPEndPoint& local_address,
                       const net::IPEndPoint& remote_address) override;
  void OnIncomingTcpConnection(const net::IPEndPoint& address, int connecting_socket_id) override;
  void OnSendComplete(const common::P2PSendPacketMetrics& send_metrics) override;
  void OnError() override;
  void OnDataReceived(const net::IPEndPoint& address,
                      const std::vector<char>& data,
                      const base::TimeTicks& timestamp) override;
  void Detach() override;

  void OnRPCBegin(
    int call_id,
    const std::string& method,
    const std::string& caller,
    const std::string& host) override;
  void OnRPCStreamRead(int call_id, const std::vector<char>& data) override;
  void OnRPCStreamWrite(int call_id) override;
  void OnRPCUnaryRead(int call_id, const std::vector<char>& data) override; 
  void OnRPCEnd(int call_id) override;
  void OnRPCStreamReadEOF(int call_id) override;
  void OnRPCSendMessageAck(int call_id, int status) override;

  void ReceiveRPCMessage(int call_id, int method_type);
  void SendRPCMessage(int call_id, const std::vector<char>& data, int method_type);
  void SendRPCMessageNow(int call_id, const std::vector<char>& data, int method_type);
  void SendRPCStatus(int call_id, int status);

  void set_state(void* state) {
    state_ = state;
  }

  void set_callbacks(const SocketCallbacks& callbacks) {
    callbacks_.OnAccept = callbacks.OnAccept;
    callbacks_.OnError = callbacks.OnError;
    callbacks_.OnSocketCreate = callbacks.OnSocketCreate;
    callbacks_.OnDataReceived = callbacks.OnDataReceived;
    callbacks_.OnRPCBegin = callbacks.OnRPCBegin;
    callbacks_.OnRPCEnd = callbacks.OnRPCEnd;
    callbacks_.OnRPCStreamRead = callbacks.OnRPCStreamRead;
    callbacks_.OnRPCStreamReadEOF = callbacks.OnRPCStreamReadEOF;
    callbacks_.OnRPCStreamWrite = callbacks.OnRPCStreamWrite;
    callbacks_.OnRPCUnaryRead = callbacks.OnRPCUnaryRead;
    callbacks_.OnRPCSendMessageAck = callbacks.OnRPCSendMessageAck;
  }

private:
  
  ~IPCSocket() override;

  void DoInit(common::P2PSocketType type,
              const net::IPEndPoint& local_address,
              uint16_t min_port,
              uint16_t max_port,
              const common::P2PHostAndIPEndPoint& remote_address);
  
  void DoInitRPC(common::P2PSocketType type,
                 const net::IPEndPoint& local_address,
                 uint16_t min_port,
                 uint16_t max_port,
                 const common::P2PHostAndIPEndPoint& remote_address,
                 const std::string& package,
                 const std::string& name);

  void SendWithPacketId(const net::IPEndPoint& address,
                        const std::vector<char>& data,
                        const rtc::PacketOptions& options,
                        uint64_t packet_id);

  void DoClose();

  SocketCallbacks callbacks_;
  void* state_;
  domain::P2PSocketDispatcher* dispatcher_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  int socket_id_;

  uint32_t random_socket_id_;
  uint32_t next_packet_id_;

  std::map<int, IPCSocketShim*> sockets_;

  net::NetworkTrafficAnnotationTag traffic_annotation_;

  DISALLOW_COPY_AND_ASSIGN(IPCSocket);
};

#endif