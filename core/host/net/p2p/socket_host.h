// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_P2P_SOCKET_HOST_H_
#define MUMBA_HOST_NET_P2P_SOCKET_HOST_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/message_loop/message_loop.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/p2p_socket_type.h"
#include "net/base/ip_endpoint.h"
#include "net/socket/datagram_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "core/host/net/p2p/webrtc_callbacks.h"

namespace IPC {
class Sender;
}

namespace net {
class URLRequestContextGetter;
}

namespace network {
class ProxyResolvingClientSocketFactory;
}

namespace rtc {
struct PacketOptions;
}

namespace host {
class P2PMessageThrottler;
class Workspace;
class Domain;

// Base class for P2P sockets.
class CONTENT_EXPORT P2PSocketHost {
 public:
  class Delegate {
  public:
   virtual ~Delegate() {}
   virtual int GetNextSocketId() = 0;
   virtual scoped_refptr<Workspace> workspace() = 0;
   virtual Domain* shell() = 0;
   virtual void DisposeSocket(P2PSocketHost* socket) = 0;
   virtual scoped_refptr<base::SingleThreadTaskRunner> acceptor_task_runner() const = 0;
  };
  static const int kStunHeaderSize = 20;
  // Creates P2PSocketHost of the specific type.
  static P2PSocketHost* Create(Delegate* delegate,
                               base::WeakPtr<IPC::Sender> message_sender,
                               int socket_id,
                               common::P2PSocketType type,
                               net::URLRequestContextGetter* url_context,
                               network::ProxyResolvingClientSocketFactory*
                                   proxy_resolving_socket_factory,
                               P2PMessageThrottler* throttler,
                               scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  virtual ~P2PSocketHost();

  // Initalizes the socket. Returns false when initialization fails.
  // |min_port| and |max_port| specify the valid range of allowed ports.
  // |min_port| must be less than or equal to |max_port|.
  // If |min_port| is zero, |max_port| must also be zero and it means all ports
  // are valid.
  // If |local_address.port()| is zero, the socket will be initialized to a port
  // in the valid range.
  // If |local_address.port()| is nonzero and not in the valid range,
  // initialization will fail.
  virtual bool Init(const common::P2PSocketOptions& options) = 0;

  // Sends |data| on the socket to |to|.
  virtual void Send(
      const net::IPEndPoint& to,
      const std::vector<char>& data,
      const rtc::PacketOptions& options,
      uint64_t packet_id,
      const net::NetworkTrafficAnnotationTag traffic_annotation) = 0;

  virtual std::unique_ptr<P2PSocketHost> AcceptIncomingTcpConnection(
      const net::IPEndPoint& remote_address) = 0;

  virtual bool SetOption(common::P2PSocketOption option, int value) = 0;

  void StartRtpDump(
      bool incoming,
      bool outgoing,
      const WebRtcRtpPacketCallback& packet_callback);
  void StopRtpDump(bool incoming, bool outgoing);

  int id() const {
    return id_;
  }

  virtual void ReceiveRpcMessage(int call_id, int method_type) = 0;
  virtual void SendRpcMessage(int call_id, int method_type, std::vector<char> data) = 0;
  virtual void SendRpcMessageNow(int call_id, int method_type, std::vector<char> data) = 0;
  virtual void SendRpcStatus(int call_id, int status_code) = 0;
  //void set_id(int id);

  virtual void DetachFromThread() {}

 protected:
  friend class P2PSocketHostTcpTestBase;

  // This should match suffix IPProtocolType defined in histograms.xml.
  enum ProtocolType { UDP = 0x1, TCP = 0x2 };

  // TODO(mallinath) - Remove this below enum and use one defined in
  // libjingle/souce/talk/p2p/base/stun.h
  enum StunMessageType {
    STUN_BINDING_REQUEST = 0x0001,
    STUN_BINDING_RESPONSE = 0x0101,
    STUN_BINDING_ERROR_RESPONSE = 0x0111,
    STUN_SHARED_SECRET_REQUEST = 0x0002,
    STUN_SHARED_SECRET_RESPONSE = 0x0102,
    STUN_SHARED_SECRET_ERROR_RESPONSE = 0x0112,
    STUN_ALLOCATE_REQUEST = 0x0003,
    STUN_ALLOCATE_RESPONSE = 0x0103,
    STUN_ALLOCATE_ERROR_RESPONSE = 0x0113,
    STUN_SEND_REQUEST = 0x0004,
    STUN_SEND_RESPONSE = 0x0104,
    STUN_SEND_ERROR_RESPONSE = 0x0114,
    STUN_DATA_INDICATION = 0x0115,
    TURN_SEND_INDICATION = 0x0016,
    TURN_DATA_INDICATION = 0x0017,
    TURN_CREATE_PERMISSION_REQUEST = 0x0008,
    TURN_CREATE_PERMISSION_RESPONSE = 0x0108,
    TURN_CREATE_PERMISSION_ERROR_RESPONSE = 0x0118,
    TURN_CHANNEL_BIND_REQUEST = 0x0009,
    TURN_CHANNEL_BIND_RESPONSE = 0x0109,
    TURN_CHANNEL_BIND_ERROR_RESPONSE = 0x0119,
  };

  enum State {
    STATE_UNINITIALIZED,
    STATE_CONNECTING,
    STATE_TLS_CONNECTING,
    STATE_OPEN,
    STATE_ERROR,
  };

  P2PSocketHost(Delegate* delegate,
                base::WeakPtr<IPC::Sender> message_sender,
                int socket_id,
                ProtocolType protocol_type);

  // Verifies that the packet |data| has a valid STUN header. In case
  // of success stores type of the message in |type|.
  static bool GetStunPacketType(const char* data, int data_size,
                                StunMessageType* type);
  static bool IsRequestOrResponse(StunMessageType type);

  static void ReportSocketError(int result, const char* histogram_name);

  // Calls |packet_dump_callback_| to record the RTP header.
  void DumpRtpPacket(const char* packet, size_t length, bool incoming);

  // A helper to dump the packet on the IO thread.
  void DumpRtpPacketOnIOThread(std::unique_ptr<uint8_t[]> packet_header,
                               size_t header_length,
                               size_t packet_length,
                               bool incoming);

  // Used by subclasses to track the metrics of delayed bytes and packets.
  void IncrementDelayedPackets();
  void IncrementTotalSentPackets();
  void IncrementDelayedBytes(uint32_t size);
  void DecrementDelayedBytes(uint32_t size);

  Delegate* delegate_;
  base::WeakPtr<IPC::Sender> message_sender_;
  int id_;
  State state_;
  bool dump_incoming_rtp_packet_;
  bool dump_outgoing_rtp_packet_;
  WebRtcRtpPacketCallback packet_dump_callback_;

  ProtocolType protocol_type_;

 private:
  // Track total delayed packets for calculating how many packets are
  // delayed by system at the end of call.
  uint32_t send_packets_delayed_total_;
  uint32_t send_packets_total_;

  // Track the maximum of consecutive delayed bytes caused by system's
  // EWOULDBLOCK.
  int32_t send_bytes_delayed_max_;
  int32_t send_bytes_delayed_cur_;

  base::WeakPtrFactory<P2PSocketHost> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(P2PSocketHost);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_P2P_SOCKET_HOST_H_
