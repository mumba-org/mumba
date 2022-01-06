// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHELL_NET_P2P_NETWORK_LIST_OBSERVER_H_
#define MUMBA_SHELL_NET_P2P_NETWORK_LIST_OBSERVER_H_

#include <vector>

namespace net {
class IPAddress;
struct NetworkInterface;
typedef std::vector<NetworkInterface> NetworkInterfaceList;
}  // namespace net

namespace application {

class NetworkListObserver {
 public:
  virtual ~NetworkListObserver() {}

  virtual void OnNetworkListChanged(
      const net::NetworkInterfaceList& list,
      const net::IPAddress& default_ipv4_local_address,
      const net::IPAddress& default_ipv6_local_address) = 0;

 protected:
  NetworkListObserver() {}
};

}  // namespace application

#endif  // MUMBA_SHELL_NET_P2P_NETWORK_LIST_OBSERVER_H_
