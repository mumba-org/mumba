// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHELL_NET_P2P_SOCKET_CLIENT_IMPL_H_
#define MUMBA_SHELL_NET_P2P_SOCKET_CLIENT_IMPL_H_

#include <stdint.h>

#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/p2p_socket_type.h"
#include "core/shared/domain/net/socket_client.h"
#include "net/base/ip_endpoint.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace base {
class SingleThreadTaskRunner;
class TimeTicks;
}  // namespace base

namespace domain {

class P2PSocketDispatcher;

// P2P socket that routes all calls over IPC.
//
// The object runs on two threads: IPC thread and delegate thread. The
// IPC thread is used to interact with P2PSocketDispatcher. All
// callbacks to the user of this class are called on the delegate
// thread which is specified in Init().
class P2PSocketClientImpl : public P2PSocketClient {
 public:
  explicit P2PSocketClientImpl(
      P2PSocketDispatcher* dispatcher,
      const net::NetworkTrafficAnnotationTag& traffic_annotation);

  // Initialize socket of the specified |type| and connected to the
  // specified |address|. |address| matters only when |type| is set to
  // P2P_SOCKET_TCP_CLIENT.
  virtual void Init(common::P2PSocketType type,
                    const net::IPEndPoint& local_address,
                    uint16_t min_port,
                    uint16_t max_port,
                    const common::P2PHostAndIPEndPoint& remote_address,
                    P2PSocketClientDelegate* delegate);

  // Send the |data| to the |address| using Differentiated Services Code Point
  // |dscp|. Return value is the unique packet_id for this packet.
  uint64_t Send(const net::IPEndPoint& address,
                const std::vector<char>& data,
                const rtc::PacketOptions& options) override;

  // Setting socket options.
  void SetOption(common::P2PSocketOption option, int value) override;

  // Must be called before the socket is destroyed. The delegate may
  // not be called after |closed_task| is executed.
  void Close() override;

  int GetSocketID() const override;

  void SetDelegate(P2PSocketClientDelegate* delegate) override;

 private:
  enum State {
    STATE_UNINITIALIZED,
    STATE_OPENING,
    STATE_OPEN,
    STATE_CLOSED,
    STATE_ERROR,
  };

  friend class P2PSocketDispatcher;

  ~P2PSocketClientImpl() override;

  // Message handlers that run on IPC thread.
  void OnSocketCreated(const net::IPEndPoint& local_address,
                       const net::IPEndPoint& remote_address) override;
  void OnIncomingTcpConnection(const net::IPEndPoint& address, int connecting_socket_id) override;
  void OnSendComplete(const common::P2PSendPacketMetrics& send_metrics) override;
  void OnError() override;
  void OnDataReceived(const net::IPEndPoint& address,
                      const std::vector<char>& data,
                      const base::TimeTicks& timestamp) override;
  
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

  // Proxy methods that deliver messages to the delegate thread.
  void DeliverOnSocketCreated(const net::IPEndPoint& local_address,
                              const net::IPEndPoint& remote_address);
  void DeliverOnIncomingTcpConnection(
      const net::IPEndPoint& address,
      scoped_refptr<P2PSocketClient> new_client);
  void DeliverOnSendComplete(const common::P2PSendPacketMetrics& send_metrics);
  void DeliverOnError();
  void DeliverOnDataReceived(const net::IPEndPoint& address,
                             const std::vector<char>& data,
                             const base::TimeTicks& timestamp);

  // Helper function to be called by Send to handle different threading
  // condition.
  void SendWithPacketId(const net::IPEndPoint& address,
                        const std::vector<char>& data,
                        const rtc::PacketOptions& options,
                        uint64_t packet_id);

  // Scheduled on the IPC thread to finish initialization.
  void DoInit(common::P2PSocketType type,
              const net::IPEndPoint& local_address,
              uint16_t min_port,
              uint16_t max_port,
              const common::P2PHostAndIPEndPoint& remote_address);

  // Scheduled on the IPC thread to finish closing the connection.
  void DoClose();

  // Called by the dispatcher when it is destroyed.
  void Detach() override;

  P2PSocketDispatcher* dispatcher_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> delegate_task_runner_;
  int socket_id_;
  P2PSocketClientDelegate* delegate_;
  State state_;
  const net::NetworkTrafficAnnotationTag traffic_annotation_;

  // These two fields are used to identify packets for tracing.
  uint32_t random_socket_id_;
  uint32_t next_packet_id_;

  DISALLOW_COPY_AND_ASSIGN(P2PSocketClientImpl);
};

}  // namespace domain

#endif  // MUMBA_SHELL_NET_P2P_SOCKET_CLIENT_IMPL_H_
