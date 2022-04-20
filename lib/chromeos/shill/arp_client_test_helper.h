// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ARP_CLIENT_TEST_HELPER_H_
#define SHILL_ARP_CLIENT_TEST_HELPER_H_

#include "shill/mock_arp_client.h"
#include "shill/net/arp_packet.h"
#include "shill/net/byte_string.h"
#include "shill/net/ip_address.h"

namespace shill {

// Class for simulate ARP client receiving ARP packets for unit test purpose.
class ArpClientTestHelper {
 public:
  explicit ArpClientTestHelper(MockArpClient* client);
  ArpClientTestHelper(const ArpClientTestHelper&) = delete;
  ArpClientTestHelper& operator=(const ArpClientTestHelper&) = delete;

  virtual ~ArpClientTestHelper();

  void GeneratePacket(uint16_t operation,
                      const IPAddress& local_ip,
                      const ByteString& local_mac,
                      const IPAddress& remote_ip,
                      const ByteString& remote_mac);

 private:
  bool SimulateReceivePacket(ArpPacket* packet, ByteString* sender);

  MockArpClient* client_;
  ArpPacket packet_;
};

}  // namespace shill

#endif  // SHILL_ARP_CLIENT_TEST_HELPER_H_
