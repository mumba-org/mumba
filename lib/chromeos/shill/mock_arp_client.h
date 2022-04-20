// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_ARP_CLIENT_H_
#define SHILL_MOCK_ARP_CLIENT_H_

#include "shill/net/arp_client.h"

#include <gmock/gmock.h>

#include "shill/net/arp_packet.h"

namespace shill {

class MockArpClient : public ArpClient {
 public:
  MockArpClient();
  MockArpClient(const MockArpClient&) = delete;
  MockArpClient& operator=(const MockArpClient&) = delete;

  ~MockArpClient() override;

  MOCK_METHOD(bool, StartReplyListener, (), (override));
  MOCK_METHOD(bool, StartRequestListener, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool,
              ReceivePacket,
              (ArpPacket*, ByteString*),
              (const, override));
  MOCK_METHOD(bool, TransmitRequest, (const ArpPacket&), (const, override));
  MOCK_METHOD(int, socket, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_MOCK_ARP_CLIENT_H_
