// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/address_manager.h"

#include <map>
#include <utility>
#include <vector>

#include <arpa/inet.h>

#include "patchpanel/net_util.h"

#include <base/rand_util.h>
#include <gtest/gtest.h>

namespace patchpanel {

TEST(AddressManager, BaseAddresses) {
  std::map<GuestType, size_t> addrs = {
      {GuestType::ARC0, Ipv4Addr(100, 115, 92, 0)},
      {GuestType::ARC_NET, Ipv4Addr(100, 115, 92, 4)},
      {GuestType::VM_TERMINA, Ipv4Addr(100, 115, 92, 24)},
      {GuestType::VM_PLUGIN, Ipv4Addr(100, 115, 93, 0)},
      {GuestType::LXD_CONTAINER, Ipv4Addr(100, 115, 92, 192)},
      {GuestType::MINIJAIL_NETNS, Ipv4Addr(100, 115, 92, 128)},
  };
  AddressManager mgr;
  for (const auto a : addrs) {
    auto subnet = mgr.AllocateIPv4Subnet(a.first);
    ASSERT_TRUE(subnet != nullptr);
    // The first address (offset 0) returned by Subnet is not the base address,
    // rather it's the first usable IP address... so the base is 1 less.
    EXPECT_EQ(a.second, htonl(ntohl(subnet->AddressAtOffset(0)) - 1));
  }
}

TEST(AddressManager, AddressesPerSubnet) {
  std::map<GuestType, size_t> addrs = {
      {GuestType::ARC0, 2},           {GuestType::ARC_NET, 2},
      {GuestType::VM_TERMINA, 2},     {GuestType::VM_PLUGIN, 6},
      {GuestType::LXD_CONTAINER, 14}, {GuestType::MINIJAIL_NETNS, 2},
  };
  AddressManager mgr;
  for (const auto a : addrs) {
    auto subnet = mgr.AllocateIPv4Subnet(a.first);
    ASSERT_TRUE(subnet != nullptr);
    EXPECT_EQ(a.second, subnet->AvailableCount());
  }
}

TEST(AddressManager, SubnetsPerPool) {
  std::map<GuestType, size_t> addrs = {
      {GuestType::ARC0, 1},          {GuestType::ARC_NET, 5},
      {GuestType::VM_TERMINA, 26},   {GuestType::VM_PLUGIN, 32},
      {GuestType::LXD_CONTAINER, 4}, {GuestType::MINIJAIL_NETNS, 16},
  };
  AddressManager mgr;
  for (const auto a : addrs) {
    std::vector<std::unique_ptr<Subnet>> subnets;
    for (size_t i = 0; i < a.second; ++i) {
      auto subnet = mgr.AllocateIPv4Subnet(a.first);
      EXPECT_TRUE(subnet != nullptr);
      subnets.emplace_back(std::move(subnet));
    }
    auto subnet = mgr.AllocateIPv4Subnet(a.first);
    EXPECT_TRUE(subnet == nullptr);
  }
}

TEST(AddressManager, SubnetIndexing) {
  AddressManager mgr;
  EXPECT_FALSE(mgr.AllocateIPv4Subnet(GuestType::ARC0, 1));
  EXPECT_FALSE(mgr.AllocateIPv4Subnet(GuestType::ARC_NET, 1));
  EXPECT_FALSE(mgr.AllocateIPv4Subnet(GuestType::VM_TERMINA, 1));
  EXPECT_TRUE(mgr.AllocateIPv4Subnet(GuestType::VM_PLUGIN, 1));
  EXPECT_FALSE(mgr.AllocateIPv4Subnet(GuestType::LXD_CONTAINER, 1));
  EXPECT_FALSE(mgr.AllocateIPv4Subnet(GuestType::MINIJAIL_NETNS, 1));
}

TEST(AddressManager, StableMacAddresses) {
  AddressManager mgr;
  EXPECT_NE(mgr.GenerateMacAddress(), mgr.GenerateMacAddress());
  EXPECT_NE(mgr.GenerateMacAddress(kAnySubnetIndex),
            mgr.GenerateMacAddress(kAnySubnetIndex));
  for (int i = 0; i < 100; ++i) {
    uint8_t index = 0;
    while (index == 0) {
      base::RandBytes(&index, 1);
    }
    EXPECT_EQ(mgr.GenerateMacAddress(index), mgr.GenerateMacAddress(index));
  }
}

}  // namespace patchpanel
