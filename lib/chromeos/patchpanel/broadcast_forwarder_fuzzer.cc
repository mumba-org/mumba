// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/broadcast_forwarder.h"

#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <shill/net/byte_string.h>
#include <shill/net/rtnl_message.h>

namespace patchpanel {

namespace {

// Test class that overrides BroadcastForwader's sending and receive functions
// with stubs.
class TestBroadcastForwarder : public BroadcastForwarder {
 public:
  TestBroadcastForwarder(const std::string& lan_ifname)
      : BroadcastForwarder(lan_ifname) {}
  TestBroadcastForwarder(const TestBroadcastForwarder&) = delete;
  TestBroadcastForwarder& operator=(const TestBroadcastForwarder&) = delete;
  ~TestBroadcastForwarder() = default;

  base::ScopedFD Bind(const std::string& ifname, uint16_t port) override {
    // Make a real socket to satisfy ScopedFD's checks.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    fds.push_back(fd);
    return base::ScopedFD(fd);
  }

  virtual base::ScopedFD BindRaw(const std::string& ifname) override {
    // Make a real socket to satisfy ScopedFD's checks.
    return Bind(ifname, 0);
  }

  std::unique_ptr<Socket> CreateSocket(base::ScopedFD fd,
                                       uint32_t addr,
                                       uint32_t broadaddr,
                                       uint32_t netmask) override {
    auto socket = std::make_unique<Socket>();
    socket->fd = std::move(fd);
    return socket;
  }

  ssize_t ReceiveMessage(int fd, struct msghdr* msg) override {
    ssize_t msg_len = std::min(payload.size(), msg->msg_iov->iov_len);
    if (msg_len > 0) {
      memcpy(msg->msg_iov->iov_base, payload.data(), msg_len);
    }
    return msg_len;
  }

  ssize_t SendTo(int fd,
                 const void* buffer,
                 size_t buffer_len,
                 const struct sockaddr_in* dst_addr) override {
    return buffer_len;
  }

  std::vector<int> fds;
  std::vector<uint8_t> payload;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  FuzzedDataProvider provider(data, size);
  std::string lan_ifname = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string guest_ifname1 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string guest_ifname2 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);

  TestBroadcastForwarder bcast_forwarder(lan_ifname);
  bcast_forwarder.AddGuest(guest_ifname1);
  bcast_forwarder.AddGuest(guest_ifname2);

  int fd_index =
      provider.ConsumeIntegralInRange<int>(0, bcast_forwarder.fds.size() - 1);
  int fd = bcast_forwarder.fds[fd_index];
  bcast_forwarder.payload = provider.ConsumeRemainingBytes<uint8_t>();
  bcast_forwarder.OnFileCanReadWithoutBlocking(fd);

  shill::RTNLMessage rtnl_msg;
  shill::ByteString bytes(bcast_forwarder.payload);
  rtnl_msg.Decode(bytes);
  bcast_forwarder.AddrMsgHandler(rtnl_msg);

  return 0;
}

}  // namespace
}  // namespace patchpanel
