// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <stdint.h>

#include <algorithm>
#include <deque>
#include <memory>
#include <random>
#include <string>
#include <utility>

#include <base/rand_util.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "patchpanel/net_util.h"
#include "patchpanel/subnet.h"
#include "patchpanel/subnet_pool.h"

using std::string;

namespace patchpanel {
namespace {

// The maximum number of subnets that can be allocated at a given time.
constexpr uint32_t kBaseAddress = Ipv4Addr(44, 55, 66, 77);
constexpr uint32_t kPrefixLength = 30;

}  // namespace

// Tests cannot create a pool with more than 32 supported subnets.
TEST(SubnetPool, MaxSubnets) {
  auto pool = SubnetPool::New(kBaseAddress, kPrefixLength, kMaxSubnets + 1);
  EXPECT_TRUE(pool == nullptr);
}

// Tests that the SubnetPool does not allocate more than max subnets at a time.
TEST(SubnetPool, AllocationRange) {
  auto pool = SubnetPool::New(kBaseAddress, kPrefixLength, kMaxSubnets);

  std::deque<std::unique_ptr<Subnet>> subnets;
  for (size_t i = 0; i < kMaxSubnets; ++i) {
    auto subnet = pool->Allocate();
    ASSERT_TRUE(subnet);

    subnets.emplace_back(std::move(subnet));
  }
  EXPECT_EQ(subnets.size(), kMaxSubnets);
  EXPECT_FALSE(pool->Allocate());
}

// Tests that subnets are properly released and reused.
TEST(SubnetPool, Release) {
  auto pool = SubnetPool::New(kBaseAddress, kPrefixLength, kMaxSubnets);

  // First allocate all the subnets.
  std::deque<std::unique_ptr<Subnet>> subnets;
  for (size_t i = 0; i < kMaxSubnets; ++i) {
    auto subnet = pool->Allocate();
    ASSERT_TRUE(subnet);

    subnets.emplace_back(std::move(subnet));
  }
  ASSERT_FALSE(pool->Allocate());

  // Now shuffle the elements.
  std::shuffle(subnets.begin(), subnets.end(),
               std::mt19937(base::RandUint64()));

  // Pop off the first element.
  auto subnet = std::move(subnets.front());
  subnets.pop_front();

  // Store the gateway and address for testing later.
  uint32_t gateway = subnet->AddressAtOffset(0);
  uint32_t address = subnet->AddressAtOffset(1);

  // Release the subnet.
  subnet.reset();

  // Get a new subnet.
  subnet = pool->Allocate();
  ASSERT_TRUE(subnet);

  EXPECT_EQ(gateway, subnet->AddressAtOffset(0));
  EXPECT_EQ(address, subnet->AddressAtOffset(1));
}

TEST(SubnetPool, Index) {
  auto pool = SubnetPool::New(kBaseAddress, kPrefixLength, kMaxSubnets);
  auto subnet = pool->Allocate(1);
  ASSERT_TRUE(subnet);
  EXPECT_FALSE(pool->Allocate(1));
  EXPECT_TRUE(pool->Allocate(0));
  EXPECT_TRUE(pool->Allocate());
  EXPECT_TRUE(pool->Allocate(2));
  EXPECT_TRUE(pool->Allocate(kMaxSubnets));
  subnet.reset();
  EXPECT_TRUE(pool->Allocate(1));
  EXPECT_FALSE(pool->Allocate(kMaxSubnets + 1));
}

}  // namespace patchpanel
