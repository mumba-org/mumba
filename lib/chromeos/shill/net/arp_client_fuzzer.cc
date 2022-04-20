// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/if_ether.h>
#include <linux/if_packet.h>

//#include <base/check.h>
#include <base/logging.h>
#include <gtest/gtest.h>

#include "shill/net/arp_client.h"
#include "shill/net/arp_packet.h"
#include "shill/net/ip_address.h"
#include "shill/net/mock_sockets.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;

namespace shill {

class ArpClientFuzz {
 public:
  ArpClientFuzz(const uint8_t* data, size_t size) : data_(data), size_(size) {}

  void Run() {
    if (size_ > ArpClient::kMaxArpPacketLength)
      return;

    ArpClient client(42 /* a perfect number (unused) */);
    MockSockets* sockets = new NiceMock<MockSockets>();
    // Passes ownership.
    client.sockets_.reset(sockets);

    EXPECT_CALL(*sockets,
                RecvFrom(_, _, ArpClient::kMaxArpPacketLength, 0, _, _))
        .WillOnce(Invoke(this, &ArpClientFuzz::RecvFrom));

    ArpPacket reply;
    ByteString sender;
    if (client.ReceivePacket(&reply, &sender)) {
      // If we think we parsed a real packet, might as well do some coherence
      // checks.
      CHECK(reply.local_ip_address().IsValid());
      CHECK(reply.remote_ip_address().IsValid());
      CHECK(reply.local_mac_address().GetLength() == ETH_ALEN);
      CHECK(reply.remote_mac_address().GetLength() == ETH_ALEN);
    }
  }

 private:
  ssize_t RecvFrom(int sockfd,
                   void* buf,
                   size_t len,
                   int flags,
                   struct sockaddr* src_addr,
                   socklen_t* addrlen) {
    size_t recvLength = std::min(len, size_);
    memcpy(buf, data_, recvLength);

    // Kernel should at least give us a valid hardware address +
    // address-length.
    sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    static const uint8_t kSenderBytes[] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    memcpy(&addr.sll_addr, kSenderBytes, sizeof(kSenderBytes));
    addr.sll_halen = sizeof(kSenderBytes);
    memcpy(src_addr, &addr, sizeof(addr));

    return recvLength;
  }

  const uint8_t* data_;
  size_t size_;
};

namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  ArpClientFuzz fuzz(data, size);
  fuzz.Run();

  return 0;
}

}  // namespace
}  // namespace shill
