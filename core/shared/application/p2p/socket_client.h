// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHELL_NET_P2P_SOCKET_CLIENT_H_
#define MUMBA_SHELL_NET_P2P_SOCKET_CLIENT_H_

#include <stdint.h>

#include <vector>

#include "base/memory/ref_counted.h"
#include "core/shared/common/p2p_socket_type.h"
#include "net/rpc/rpc.h"
#include "net/base/ip_endpoint.h"

namespace rtc {
struct PacketOptions;
};

namespace application {

class P2PSocketClientDelegate;

// P2P socket that routes all calls over IPC.
// Note that while ref-counting is thread-safe, all methods must be
// called on the same thread.
class P2PSocketClient : public base::RefCountedThreadSafe<P2PSocketClient> {
 public:
  // Send the |data| to the |address| using Differentiated Services Code Point
  // |dscp|. Return value is the unique packet_id for this packet.
  virtual uint64_t Send(const net::IPEndPoint& address,
                        const std::vector<char>& data,
                        const rtc::PacketOptions& options) = 0;

  virtual void SetOption(common::P2PSocketOption option, int value) = 0;

  // Must be called before the socket is destroyed.
  virtual void Close() = 0;

  virtual int GetSocketID() const = 0;
  virtual void SetDelegate(P2PSocketClientDelegate* delegate) = 0;
  virtual void OnSocketCreated(const net::IPEndPoint& local_address,
                       const net::IPEndPoint& remote_address) = 0;
  virtual void OnIncomingTcpConnection(const net::IPEndPoint& address, int connecting_socket_id) = 0;
  virtual void OnSendComplete(const common::P2PSendPacketMetrics& send_metrics) = 0;
  virtual void OnError() = 0;
  virtual void OnDataReceived(const net::IPEndPoint& address,
                      const std::vector<char>& data,
                      const base::TimeTicks& timestamp) = 0;
  virtual void Detach() = 0;

  virtual void OnRPCBegin(
    int call_id,
    const std::string& method,
    const std::string& caller,
    const std::string& host) = 0;
  virtual void OnRPCStreamRead(int call_id, const std::vector<char>& data) = 0;
  virtual void OnRPCStreamWrite(int call_id) = 0;
  virtual void OnRPCUnaryRead(int call_id, const std::vector<char>& data) = 0; 
  virtual void OnRPCEnd(int call_id) = 0;
  virtual void OnRPCStreamReadEOF(int call_id) = 0;
  virtual void OnRPCSendMessageAck(int call_id, int status) = 0;

 protected:
  P2PSocketClient() {}
  virtual ~P2PSocketClient() {}

 private:
  // Calls destructor.
  friend class base::RefCountedThreadSafe<P2PSocketClient>;
};
}  // namespace application

#endif  // MUMBA_SHELL_NET_P2P_SOCKET_CLIENT_H_
