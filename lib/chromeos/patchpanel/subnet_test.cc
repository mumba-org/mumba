// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/subnet.h"

#include <arpa/inet.h>
#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>

#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {

constexpr size_t kContainerBaseAddress = Ipv4Addr(100, 115, 92, 192);
constexpr size_t kVmBaseAddress = Ipv4Addr(100, 115, 92, 24);
constexpr size_t kPluginBaseAddress = Ipv4Addr(100, 115, 92, 128);

constexpr size_t kContainerSubnetPrefixLength = 28;
constexpr size_t kVmSubnetPrefixLength = 30;
constexpr size_t kPluginSubnetPrefixLength = 28;

uint32_t AddOffset(uint32_t base_addr_no, uint32_t offset_ho) {
  return htonl(ntohl(base_addr_no) + offset_ho);
}

// kExpectedAvailableCount[i] == AvailableCount() for subnet with prefix_length
// i.
constexpr size_t kExpectedAvailableCount[] = {
    0xfffffffe, 0x7ffffffe, 0x3ffffffe, 0x1ffffffe, 0xffffffe, 0x7fffffe,
    0x3fffffe,  0x1fffffe,  0xfffffe,   0x7ffffe,   0x3ffffe,  0x1ffffe,
    0xffffe,    0x7fffe,    0x3fffe,    0x1fffe,    0xfffe,    0x7ffe,
    0x3ffe,     0x1ffe,     0xffe,      0x7fe,      0x3fe,     0x1fe,
    0xfe,       0x7e,       0x3e,       0x1e,       0xe,       0x6,
    0x2,        0x0,
};

// kExpectedNetmask[i] == Netmask() for subnet with prefix_length i.
constexpr uint32_t kExpectedNetmask[] = {
    Ipv4Addr(0, 0, 0, 0),         Ipv4Addr(128, 0, 0, 0),
    Ipv4Addr(192, 0, 0, 0),       Ipv4Addr(224, 0, 0, 0),
    Ipv4Addr(240, 0, 0, 0),       Ipv4Addr(248, 0, 0, 0),
    Ipv4Addr(252, 0, 0, 0),       Ipv4Addr(254, 0, 0, 0),
    Ipv4Addr(255, 0, 0, 0),       Ipv4Addr(255, 128, 0, 0),
    Ipv4Addr(255, 192, 0, 0),     Ipv4Addr(255, 224, 0, 0),
    Ipv4Addr(255, 240, 0, 0),     Ipv4Addr(255, 248, 0, 0),
    Ipv4Addr(255, 252, 0, 0),     Ipv4Addr(255, 254, 0, 0),
    Ipv4Addr(255, 255, 0, 0),     Ipv4Addr(255, 255, 128, 0),
    Ipv4Addr(255, 255, 192, 0),   Ipv4Addr(255, 255, 224, 0),
    Ipv4Addr(255, 255, 240, 0),   Ipv4Addr(255, 255, 248, 0),
    Ipv4Addr(255, 255, 252, 0),   Ipv4Addr(255, 255, 254, 0),
    Ipv4Addr(255, 255, 255, 0),   Ipv4Addr(255, 255, 255, 128),
    Ipv4Addr(255, 255, 255, 192), Ipv4Addr(255, 255, 255, 224),
    Ipv4Addr(255, 255, 255, 240), Ipv4Addr(255, 255, 255, 248),
    Ipv4Addr(255, 255, 255, 252), Ipv4Addr(255, 255, 255, 254),
};

// kExpectedPrefix[i] == Prefix() for subnet with 4 * i offset to
// |kVmBaseAddress|.
constexpr uint32_t kExpectedPrefix[] = {
    Ipv4Addr(100, 115, 92, 24),  Ipv4Addr(100, 115, 92, 28),
    Ipv4Addr(100, 115, 92, 32),  Ipv4Addr(100, 115, 92, 36),
    Ipv4Addr(100, 115, 92, 40),  Ipv4Addr(100, 115, 92, 44),
    Ipv4Addr(100, 115, 92, 48),  Ipv4Addr(100, 115, 92, 52),
    Ipv4Addr(100, 115, 92, 56),  Ipv4Addr(100, 115, 92, 60),
    Ipv4Addr(100, 115, 92, 64),  Ipv4Addr(100, 115, 92, 68),
    Ipv4Addr(100, 115, 92, 72),  Ipv4Addr(100, 115, 92, 76),
    Ipv4Addr(100, 115, 92, 80),  Ipv4Addr(100, 115, 92, 84),
    Ipv4Addr(100, 115, 92, 88),  Ipv4Addr(100, 115, 92, 92),
    Ipv4Addr(100, 115, 92, 96),  Ipv4Addr(100, 115, 92, 100),
    Ipv4Addr(100, 115, 92, 104), Ipv4Addr(100, 115, 92, 108),
    Ipv4Addr(100, 115, 92, 112), Ipv4Addr(100, 115, 92, 116),
    Ipv4Addr(100, 115, 92, 120), Ipv4Addr(100, 115, 92, 124),
    Ipv4Addr(100, 115, 92, 128), Ipv4Addr(100, 115, 92, 132),
    Ipv4Addr(100, 115, 92, 136), Ipv4Addr(100, 115, 92, 140),
    Ipv4Addr(100, 115, 92, 144), Ipv4Addr(100, 115, 92, 148),
};

// kExpectedCidrString[i] == ToCidrString() for subnet with 4 * i offset to
// |kVmBaseAddress|.
const char* kExpectedCidrString[] = {
    "100.115.92.24/30",  "100.115.92.28/30",  "100.115.92.32/30",
    "100.115.92.36/30",  "100.115.92.40/30",  "100.115.92.44/30",
    "100.115.92.48/30",  "100.115.92.52/30",  "100.115.92.56/30",
    "100.115.92.60/30",  "100.115.92.64/30",  "100.115.92.68/30",
    "100.115.92.72/30",  "100.115.92.76/30",  "100.115.92.80/30",
    "100.115.92.84/30",  "100.115.92.88/30",  "100.115.92.92/30",
    "100.115.92.96/30",  "100.115.92.100/30", "100.115.92.104/30",
    "100.115.92.108/30", "100.115.92.112/30", "100.115.92.116/30",
    "100.115.92.120/30", "100.115.92.124/30", "100.115.92.128/30",
    "100.115.92.132/30", "100.115.92.136/30", "100.115.92.140/30",
    "100.115.92.144/30", "100.115.92.148/30",
};

class VmSubnetTest : public ::testing::TestWithParam<size_t> {};
class ContainerSubnetTest : public ::testing::TestWithParam<size_t> {};
class PrefixTest : public ::testing::TestWithParam<size_t> {};

void SetTrue(bool* value) {
  *value = true;
}

}  // namespace

TEST_P(VmSubnetTest, Prefix) {
  size_t index = GetParam();
  Subnet subnet(AddOffset(kVmBaseAddress, index * 4), kVmSubnetPrefixLength,
                base::DoNothing());

  EXPECT_EQ(kExpectedPrefix[index], subnet.Prefix());
}

TEST_P(VmSubnetTest, CidrString) {
  size_t index = GetParam();
  Subnet subnet(AddOffset(kVmBaseAddress, index * 4), kVmSubnetPrefixLength,
                base::DoNothing());

  EXPECT_EQ(std::string(kExpectedCidrString[index]), subnet.ToCidrString());
  EXPECT_EQ(kExpectedCidrString[index], subnet.ToCidrString());
}

TEST_P(VmSubnetTest, AddressAtOffset) {
  size_t index = GetParam();
  Subnet subnet(AddOffset(kVmBaseAddress, index * 4), kVmSubnetPrefixLength,
                base::DoNothing());

  for (uint32_t offset = 0; offset < subnet.AvailableCount(); ++offset) {
    uint32_t address = AddOffset(kVmBaseAddress, index * 4 + offset + 1);
    EXPECT_EQ(address, subnet.AddressAtOffset(offset));
  }
}

INSTANTIATE_TEST_SUITE_P(AllValues,
                         VmSubnetTest,
                         ::testing::Range(size_t{0}, size_t{26}));

TEST_P(ContainerSubnetTest, AddressAtOffset) {
  size_t index = GetParam();
  Subnet subnet(AddOffset(kContainerBaseAddress, index * 16),
                kContainerSubnetPrefixLength, base::DoNothing());

  for (uint32_t offset = 0; offset < subnet.AvailableCount(); ++offset) {
    uint32_t address =
        AddOffset(kContainerBaseAddress, index * 16 + offset + 1);
    EXPECT_EQ(address, subnet.AddressAtOffset(offset));
  }
}

INSTANTIATE_TEST_SUITE_P(AllValues,
                         ContainerSubnetTest,
                         ::testing::Range(size_t{1}, size_t{4}));

TEST_P(PrefixTest, AvailableCount) {
  size_t prefix_length = GetParam();

  Subnet subnet(0, prefix_length, base::DoNothing());
  EXPECT_EQ(kExpectedAvailableCount[prefix_length], subnet.AvailableCount());
}

TEST_P(PrefixTest, Netmask) {
  size_t prefix_length = GetParam();

  Subnet subnet(0, prefix_length, base::DoNothing());
  EXPECT_EQ(kExpectedNetmask[prefix_length], subnet.Netmask());
}

INSTANTIATE_TEST_SUITE_P(AllValues,
                         PrefixTest,
                         ::testing::Range(size_t{8}, size_t{32}));

TEST(SubtnetAddress, StringConversion) {
  Subnet container_subnet(kContainerBaseAddress, kContainerSubnetPrefixLength,
                          base::DoNothing());
  EXPECT_EQ("100.115.92.192/28", container_subnet.ToCidrString());
  {
    EXPECT_EQ("100.115.92.193",
              container_subnet.AllocateAtOffset(0)->ToIPv4String());
    EXPECT_EQ("100.115.92.194",
              container_subnet.AllocateAtOffset(1)->ToIPv4String());
    EXPECT_EQ("100.115.92.205",
              container_subnet.AllocateAtOffset(12)->ToIPv4String());
    EXPECT_EQ("100.115.92.206",
              container_subnet.AllocateAtOffset(13)->ToIPv4String());
  }
  {
    EXPECT_EQ("100.115.92.193/28",
              container_subnet.AllocateAtOffset(0)->ToCidrString());
    EXPECT_EQ("100.115.92.194/28",
              container_subnet.AllocateAtOffset(1)->ToCidrString());
    EXPECT_EQ("100.115.92.205/28",
              container_subnet.AllocateAtOffset(12)->ToCidrString());
    EXPECT_EQ("100.115.92.206/28",
              container_subnet.AllocateAtOffset(13)->ToCidrString());
  }

  Subnet vm_subnet(kVmBaseAddress, kVmSubnetPrefixLength, base::DoNothing());
  EXPECT_EQ("100.115.92.24/30", vm_subnet.ToCidrString());
  {
    EXPECT_EQ("100.115.92.25", vm_subnet.AllocateAtOffset(0)->ToIPv4String());
    EXPECT_EQ("100.115.92.26", vm_subnet.AllocateAtOffset(1)->ToIPv4String());
  }
  {
    EXPECT_EQ("100.115.92.25/30",
              vm_subnet.AllocateAtOffset(0)->ToCidrString());
    EXPECT_EQ("100.115.92.26/30",
              vm_subnet.AllocateAtOffset(1)->ToCidrString());
  }

  Subnet plugin_subnet(kPluginBaseAddress, kPluginSubnetPrefixLength,
                       base::DoNothing());
  EXPECT_EQ("100.115.92.128/28", plugin_subnet.ToCidrString());
  {
    EXPECT_EQ("100.115.92.129",
              plugin_subnet.AllocateAtOffset(0)->ToIPv4String());
    EXPECT_EQ("100.115.92.130",
              plugin_subnet.AllocateAtOffset(1)->ToIPv4String());
    EXPECT_EQ("100.115.92.141",
              plugin_subnet.AllocateAtOffset(12)->ToIPv4String());
    EXPECT_EQ("100.115.92.142",
              plugin_subnet.AllocateAtOffset(13)->ToIPv4String());
  }
  {
    EXPECT_EQ("100.115.92.129/28",
              plugin_subnet.AllocateAtOffset(0)->ToCidrString());
    EXPECT_EQ("100.115.92.130/28",
              plugin_subnet.AllocateAtOffset(1)->ToCidrString());
    EXPECT_EQ("100.115.92.141/28",
              plugin_subnet.AllocateAtOffset(12)->ToCidrString());
    EXPECT_EQ("100.115.92.142/28",
              plugin_subnet.AllocateAtOffset(13)->ToCidrString());
  }
}

// Tests that the Subnet runs the provided cleanup callback when it gets
// destroyed.
TEST(Subnet, Cleanup) {
  bool called = false;

  { Subnet subnet(0, 24, base::BindOnce(&SetTrue, &called)); }

  EXPECT_TRUE(called);
}

// Tests that the subnet rejects attempts to allocate addresses outside its
// range.
TEST(PluginSubnet, OutOfBounds) {
  Subnet subnet(kPluginBaseAddress, kPluginSubnetPrefixLength,
                base::DoNothing());

  EXPECT_FALSE(subnet.Allocate(htonl(ntohl(kPluginBaseAddress) - 1)));
  EXPECT_FALSE(subnet.Allocate(kPluginBaseAddress));
  EXPECT_FALSE(subnet.Allocate(AddOffset(
      kPluginBaseAddress, (1ull << (32 - kPluginSubnetPrefixLength)) - 1)));
  EXPECT_FALSE(subnet.Allocate(AddOffset(
      kPluginBaseAddress, (1ull << (32 - kPluginSubnetPrefixLength)))));
}

// Tests that the subnet rejects attempts to allocate the same address twice.
TEST(PluginSubnet, DuplicateAddress) {
  Subnet subnet(kPluginBaseAddress, kPluginSubnetPrefixLength,
                base::DoNothing());

  auto addr = subnet.Allocate(AddOffset(kPluginBaseAddress, 1));
  EXPECT_TRUE(addr);
  EXPECT_FALSE(subnet.Allocate(AddOffset(kPluginBaseAddress, 1)));
}

// Tests that the subnet allows allocating all addresses in the subnet's range.
TEST(PluginSubnet, Allocate) {
  Subnet subnet(kPluginBaseAddress, kPluginSubnetPrefixLength,
                base::DoNothing());

  std::vector<std::unique_ptr<SubnetAddress>> addrs;
  addrs.reserve(subnet.AvailableCount());

  for (size_t offset = 0; offset < subnet.AvailableCount(); ++offset) {
    // Offset by one since the network id is not allocatable.
    auto addr = subnet.Allocate(AddOffset(kPluginBaseAddress, offset + 1));
    EXPECT_TRUE(addr);
    EXPECT_EQ(AddOffset(kPluginBaseAddress, offset + 1), addr->Address());
    addrs.emplace_back(std::move(addr));
  }
}
// Tests that the subnet allows allocating all addresses in the subnet's range
// using an offset.
TEST(PluginSubnet, AllocateAtOffset) {
  Subnet subnet(kPluginBaseAddress, kPluginSubnetPrefixLength,
                base::DoNothing());

  std::vector<std::unique_ptr<SubnetAddress>> addrs;
  addrs.reserve(subnet.AvailableCount());

  for (size_t offset = 0; offset < subnet.AvailableCount(); ++offset) {
    auto addr = subnet.AllocateAtOffset(offset);
    EXPECT_TRUE(addr);
    EXPECT_EQ(AddOffset(kPluginBaseAddress, offset + 1), addr->Address());
    addrs.emplace_back(std::move(addr));
  }
}

// Tests that the subnet frees addresses when they are destroyed.
TEST(PluginSubnet, Free) {
  Subnet subnet(kPluginBaseAddress, kPluginSubnetPrefixLength,
                base::DoNothing());

  {
    auto addr = subnet.Allocate(AddOffset(kPluginBaseAddress, 1));
    EXPECT_TRUE(addr);
  }

  EXPECT_TRUE(subnet.Allocate(AddOffset(kPluginBaseAddress, 1)));
}

}  // namespace patchpanel
