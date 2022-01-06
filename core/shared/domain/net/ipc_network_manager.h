// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHELL_NET_P2P_IPC_NETWORK_MANAGER_H_
#define MUMBA_SHELL_NET_P2P_IPC_NETWORK_MANAGER_H_

#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/weak_ptr.h"
#include "core/shared/common/content_export.h"
#include "core/shared/domain/net/network_list_manager.h"
#include "core/shared/domain/net/network_list_observer.h"
#include "third_party/webrtc/rtc_base/network.h"

namespace net {
class IPAddress;
}

namespace domain {

// IpcNetworkManager is a NetworkManager for libjingle that gets a
// list of network interfaces from the browser.
class IpcNetworkManager : public rtc::NetworkManagerBase,
                          public NetworkListObserver {
 public:
  // Constructor doesn't take ownership of the |network_list_manager|.
  CONTENT_EXPORT IpcNetworkManager(NetworkListManager* network_list_manager);
  ~IpcNetworkManager() override;

  // rtc:::NetworkManager:
  void StartUpdating() override;
  void StopUpdating() override;

  // P2PSocketDispatcher::NetworkListObserver interface.
  void OnNetworkListChanged(
      const net::NetworkInterfaceList& list,
      const net::IPAddress& default_ipv4_local_address,
      const net::IPAddress& default_ipv6_local_address) override;

 private:
  void SendNetworksChangedSignal();

  NetworkListManager* network_list_manager_;
  int start_count_;
  bool network_list_received_;

  base::WeakPtrFactory<IpcNetworkManager> weak_factory_;
};

}  // namespace domain

#endif  // MUMBA_SHELL_NET_P2P_IPC_NETWORK_MANAGER_H_
