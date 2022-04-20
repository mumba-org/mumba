// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/multicast_forwarder.h"

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

#include "patchpanel/net_util.h"

namespace patchpanel {

constexpr const struct in_addr kLanIp = {.s_addr = Ipv4Addr(192, 168, 1, 1)};
constexpr const struct in_addr kGuestIp = {.s_addr = Ipv4Addr(100, 115, 92, 2)};

namespace {

// Test class that overrides MulticastForwarder's sending and receive functions
// with stubs.
class TestMulticastForwarder : public MulticastForwarder {
 public:
  TestMulticastForwarder(const std::string& lan_ifname,
                         uint32_t mcast_addr,
                         const std::string& mcast_addr6,
                         uint16_t port)
      : MulticastForwarder(lan_ifname, mcast_addr, mcast_addr6, port) {}
  TestMulticastForwarder(const TestMulticastForwarder&) = delete;
  TestMulticastForwarder& operator=(const TestMulticastForwarder&) = delete;
  ~TestMulticastForwarder() = default;

  base::ScopedFD Bind(sa_family_t sa_family,
                      const std::string& ifname) override {
    // Make a real socket to satisfy ScopedFD's checks.
    int fd = socket(sa_family, SOCK_DGRAM, 0);
    fds.push_back(fd);
    return base::ScopedFD(fd);
  }

  std::unique_ptr<MulticastForwarder::Socket> CreateSocket(
      base::ScopedFD fd, sa_family_t sa_family) override {
    auto socket = std::make_unique<Socket>();
    socket->fd = std::move(fd);
    return socket;
  }

  bool SendTo(uint16_t src_port,
              const void* data,
              ssize_t len,
              const struct sockaddr* dst,
              socklen_t dst_len) override {
    return true;
  }

  bool SendToGuests(const void* data,
                    ssize_t len,
                    const struct sockaddr* dst,
                    socklen_t dst_len,
                    int ignore_fd) override {
    return true;
  }

  ssize_t Receive(int fd,
                  char* buffer,
                  size_t buffer_size,
                  struct sockaddr* src_addr,
                  socklen_t* addrlen) override {
    *addrlen = std::min(src_sockaddr.size(), (size_t)*addrlen);
    if (*addrlen > 0) {
      memcpy(src_addr, src_sockaddr.data(), *addrlen);
    }
    buffer_size = std::min(payload.size(), buffer_size);
    if (buffer_size > 0) {
      memcpy(buffer, payload.data(), buffer_size);
    }
    src_addr->sa_family = sa_family;
    return true;
  }

  std::vector<int> fds;
  sa_family_t sa_family;
  std::vector<uint8_t> src_sockaddr;
  std::vector<uint8_t> payload;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  // Copy the input data so that TranslateMdnsIp can mutate it.
  char* payload = new char[size];
  memcpy(payload, data, size);
  MulticastForwarder::TranslateMdnsIp(kLanIp, kGuestIp, payload, size);
  delete[] payload;

  FuzzedDataProvider provider(data, size);
  std::string lan_ifname = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string guest_ifname1 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string guest_ifname2 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  uint32_t mcast_addr = provider.ConsumeIntegral<uint32_t>();
  struct in6_addr ipv6_addr;
  memset(&ipv6_addr, 0, sizeof(ipv6_addr));
  std::vector<uint8_t> ipv6_addr_bytes =
      provider.ConsumeBytes<uint8_t>(sizeof(ipv6_addr.s6_addr));
  std::copy(ipv6_addr_bytes.begin(), ipv6_addr_bytes.end(), ipv6_addr.s6_addr);
  std::string mcast_addr6 = IPv6AddressToString(ipv6_addr);

  TestMulticastForwarder mcast_forwarder(lan_ifname, mcast_addr, mcast_addr6,
                                         kMdnsPort);
  mcast_forwarder.Init();
  mcast_forwarder.AddGuest(guest_ifname1);
  mcast_forwarder.AddGuest(guest_ifname2);

  int fd_index =
      provider.ConsumeIntegralInRange<int>(0, mcast_forwarder.fds.size() - 1);
  int fd = mcast_forwarder.fds[fd_index];
  if (provider.ConsumeBool()) {
    mcast_forwarder.sa_family = AF_INET;
    mcast_forwarder.src_sockaddr =
        provider.ConsumeBytes<uint8_t>(sizeof(struct sockaddr_in));
  } else {
    mcast_forwarder.sa_family = AF_INET6;
    mcast_forwarder.src_sockaddr =
        provider.ConsumeBytes<uint8_t>(sizeof(struct sockaddr_in6));
  }
  mcast_forwarder.payload = provider.ConsumeRemainingBytes<uint8_t>();
  mcast_forwarder.OnFileCanReadWithoutBlocking(fd, mcast_forwarder.sa_family);

  return 0;
}

}  // namespace
}  // namespace patchpanel
