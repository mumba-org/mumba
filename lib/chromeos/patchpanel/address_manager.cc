// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/address_manager.h"

#include <base/logging.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

namespace {

// The 100.115.92.0/24 subnet is reserved and not publicly routable. This subnet
// is sliced into the following IP pools for use among the various usages:
// +---------------+------------+----------------------------------------------+
// |   IP Range    |    Guest   |                                              |
// +---------------+------------+----------------------------------------------+
// | 0       (/30) | ARC/ARCVM  | Used for ARC management interface arc0       |
// | 4-20    (/30) | ARC/ARCVM  | Used to expose multiple host networks to ARC |
// | 24-124  (/30) | Termina VM | Used by Crostini                             |
// | 128-188 (/30) | Host netns | Used for netns hosting minijailed services   |
// | 192-252 (/28) | Containers | Used by Crostini LXD user containers         |
// +---------------+------------+----------------------------------------------+
//
// The 100.115.93.0/24 subnet is reserved for plugin VMs.

}  // namespace

AddressManager::AddressManager() {
  for (auto g : {GuestType::ARC0, GuestType::ARC_NET, GuestType::VM_TERMINA,
                 GuestType::VM_PLUGIN, GuestType::LXD_CONTAINER,
                 GuestType::MINIJAIL_NETNS}) {
    uint32_t base_addr;
    uint32_t prefix_length = 30;
    uint32_t subnets = 1;
    switch (g) {
      case GuestType::ARC0:
        base_addr = Ipv4Addr(100, 115, 92, 0);
        break;
      case GuestType::ARC_NET:
        base_addr = Ipv4Addr(100, 115, 92, 4);
        subnets = 5;
        break;
      case GuestType::VM_TERMINA:
        base_addr = Ipv4Addr(100, 115, 92, 24);
        subnets = 26;
        break;
      case GuestType::MINIJAIL_NETNS:
        base_addr = Ipv4Addr(100, 115, 92, 128);
        prefix_length = 30;
        subnets = 16;
        break;
      case GuestType::LXD_CONTAINER:
        base_addr = Ipv4Addr(100, 115, 92, 192);
        prefix_length = 28;
        subnets = 4;
        break;
      case GuestType::VM_PLUGIN:
        base_addr = Ipv4Addr(100, 115, 93, 0);
        prefix_length = 29;
        subnets = 32;
        break;
    }
    pools_.emplace(g, SubnetPool::New(base_addr, prefix_length, subnets));
  }
}

MacAddress AddressManager::GenerateMacAddress(uint8_t index) {
  return index == kAnySubnetIndex ? mac_addrs_.Generate()
                                  : mac_addrs_.GetStable(index);
}

std::unique_ptr<Subnet> AddressManager::AllocateIPv4Subnet(GuestType guest,
                                                           uint32_t index) {
  if (index > 0 && guest != GuestType::VM_PLUGIN) {
    LOG(ERROR) << "Subnet indexing not supported for guest";
    return nullptr;
  }
  const auto it = pools_.find(guest);
  return (it != pools_.end()) ? it->second->Allocate(index) : nullptr;
}

}  // namespace patchpanel
