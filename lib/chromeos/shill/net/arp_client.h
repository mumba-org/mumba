// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_ARP_CLIENT_H_
#define SHILL_NET_ARP_CLIENT_H_

#include <memory>

#include "shill/net/shill_export.h"

namespace shill {

class ArpPacket;
class ByteString;
class Sockets;
class ScopedSocketCloser;

// ArpClient task of creating ARP-capable sockets, as well as
// transmitting requests on and receiving responses from such
// sockets.
class SHILL_EXPORT ArpClient {
 public:
  explicit ArpClient(int interface_index);
  ArpClient(const ArpClient&) = delete;
  ArpClient& operator=(const ArpClient&) = delete;

  virtual ~ArpClient();

  // Create a socket for reception of ARP replies, and packet trasmission.
  // Returns true if successful, false otherwise.
  virtual bool StartReplyListener();

  // Create a socket for reception of ARP requests, and packet trasmission.
  // Returns true if successful, false otherwise.
  virtual bool StartRequestListener();

  // Destroy the client socket.
  virtual void Stop();

  // Receive an ARP request or reply and parse its contents into |packet|.
  // Also return the sender's MAC address (which may be different from the
  // MAC address in the ARP response) in |sender|.  Returns true on
  // succes, false otherwise.
  virtual bool ReceivePacket(ArpPacket* packet, ByteString* sender) const;

  // Send a formatted ARP request from |packet|.  Returns true on
  // success, false otherwise.
  virtual bool TransmitRequest(const ArpPacket& packet) const;

  virtual int socket() const { return socket_; }

  bool IsStarted() { return socket_closer_.get(); }

 private:
  friend class ArpClientFuzz;
  friend class ArpClientTest;

  // Offset of the ARP OpCode within a captured ARP packet.
  static const size_t kArpOpOffset;

  // The largest packet we expect to receive as an ARP client.
  static const size_t kMaxArpPacketLength;

  // Start an ARP listener that listens for |arp_opcode| ARP packets.
  bool Start(uint16_t arp_opcode);
  bool CreateSocket(uint16_t arp_opcode);

  const int interface_index_;
  std::unique_ptr<Sockets> sockets_;
  std::unique_ptr<ScopedSocketCloser> socket_closer_;
  int socket_;
};

}  // namespace shill

#endif  // SHILL_NET_ARP_CLIENT_H_
