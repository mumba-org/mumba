// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_BROADCAST_FORWARDER_H_
#define PATCHPANEL_BROADCAST_FORWARDER_H_

#include <sys/socket.h>
#include <sys/types.h>

#include <map>
#include <memory>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <shill/net/rtnl_listener.h>
#include <shill/net/rtnl_message.h>

#include "patchpanel/net_util.h"
#include "patchpanel/shill_client.h"

namespace patchpanel {

constexpr uint32_t kBcastAddr = Ipv4Addr(255, 255, 255, 255);

// Listens to broadcast messages sent by applications and forwards them between
// network interfaces of host and guest.
// BroadcastForwarder assumes that guest addresses, including broadcast and
// netmask, are constant.
class BroadcastForwarder {
 public:
  explicit BroadcastForwarder(const std::string& dev_ifname);
  BroadcastForwarder(const BroadcastForwarder&) = delete;
  BroadcastForwarder& operator=(const BroadcastForwarder&) = delete;

  virtual ~BroadcastForwarder() = default;

  // Starts listening to RTNL IPv4 address events.
  void Init();

  // Starts or stops forwarding broadcast packets to and from a downstream
  // guest on network interface |br_ifname|.
  bool AddGuest(const std::string& br_ifname);
  void RemoveGuest(const std::string& br_ifname);

  // Receives a broadcast packet from the network or from a guest and forwards
  // it.
  void OnFileCanReadWithoutBlocking(int fd);

  // Callback from RTNetlink listener, invoked when the lan interface IPv4
  // address is changed.
  void AddrMsgHandler(const shill::RTNLMessage& msg);

 protected:
  // Socket is used to keep track of an fd and its watcher.
  // It also stores addresses corresponding to the interface it is bound to.
  struct Socket {
    base::ScopedFD fd;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher;
    uint32_t addr;
    uint32_t broadaddr;
    uint32_t netmask;
  };

  // Bind will create a broadcast socket and return its fd.
  // This is used for sending broadcasts.
  virtual base::ScopedFD Bind(const std::string& ifname, uint16_t port);

  // BindRaw will create a broadcast socket that listens to all IP packets.
  // It filters the packets to only broadcast packets that is sent by
  // applications.
  // This is used to listen on broadcasts.
  virtual base::ScopedFD BindRaw(const std::string& ifname);

  // SendToNetwork sends |data| using a socket bound to |src_port| and
  // |dev_ifname_| using a temporary socket.
  bool SendToNetwork(uint16_t src_port,
                     const void* data,
                     ssize_t len,
                     const struct sockaddr_in& dst);

  // SendToGuests will forward the broadcast packet to all Chrome OS guests'
  // (ARC++, Crostini, etc) internal fd.
  bool SendToGuests(const void* ip_pkt,
                    ssize_t len,
                    const struct sockaddr_in& dst);

  // Wrapper around libc recvmsg, allowing override in fuzzer tests.
  virtual ssize_t ReceiveMessage(int fd, struct msghdr* msg);

  // Wrapper around libc sendto, allowing override in fuzzer tests.
  virtual ssize_t SendTo(int fd,
                         const void* buffer,
                         size_t buffer_len,
                         const struct sockaddr_in* dst_addr);

  virtual std::unique_ptr<Socket> CreateSocket(base::ScopedFD fd,
                                               uint32_t addr,
                                               uint32_t broadaddr,
                                               uint32_t netmask);

 private:
  // Listens for RTMGRP_IPV4_IFADDR messages and invokes AddrMsgHandler.
  std::unique_ptr<shill::RTNLListener> addr_listener_;
  // Name of the physical interface that this forwarder is bound to.
  const std::string dev_ifname_;
  // IPv4 socket bound by this forwarder onto |dev_ifname_|.
  std::unique_ptr<Socket> dev_socket_;
  // Mapping from guest bridge interface name to its sockets.
  std::map<std::string, std::unique_ptr<Socket>> br_sockets_;

  base::WeakPtrFactory<BroadcastForwarder> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_BROADCAST_FORWARDER_H_
