// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/arp_client_test_helper.h"

#include <gtest/gtest.h>

using testing::_;
using testing::Invoke;

namespace shill {

ArpClientTestHelper::ArpClientTestHelper(MockArpClient* client)
    : client_(client) {}

ArpClientTestHelper::~ArpClientTestHelper() = default;

void ArpClientTestHelper::GeneratePacket(uint16_t operation,
                                         const IPAddress& local_ip,
                                         const ByteString& local_mac,
                                         const IPAddress& remote_ip,
                                         const ByteString& remote_mac) {
  packet_.set_operation(operation);
  packet_.set_local_ip_address(local_ip);
  packet_.set_local_mac_address(local_mac);
  packet_.set_remote_ip_address(remote_ip);
  packet_.set_remote_mac_address(remote_mac);

  EXPECT_CALL(*client_, ReceivePacket(_, _))
      .WillOnce(Invoke(this, &ArpClientTestHelper::SimulateReceivePacket));
}

bool ArpClientTestHelper::SimulateReceivePacket(ArpPacket* packet,
                                                ByteString* sender) {
  packet->set_operation(packet_.operation());
  packet->set_local_ip_address(packet_.local_ip_address());
  packet->set_local_mac_address(packet_.local_mac_address());
  packet->set_remote_ip_address(packet_.remote_ip_address());
  packet->set_remote_mac_address(packet_.remote_mac_address());
  return true;
}

}  // namespace shill
