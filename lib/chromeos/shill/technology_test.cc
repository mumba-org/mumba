// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/technology.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/error.h"

using testing::ElementsAre;

namespace shill {

TEST(TechnologyTest, CreateFromName) {
  EXPECT_EQ(Technology::kEthernet, Technology::CreateFromName("ethernet"));
  EXPECT_EQ(Technology::kEthernetEap,
            Technology::CreateFromName("etherneteap"));
  EXPECT_EQ(Technology::kWiFi, Technology::CreateFromName("wifi"));
  EXPECT_EQ(Technology::kCellular, Technology::CreateFromName("cellular"));
  EXPECT_EQ(Technology::kTunnel, Technology::CreateFromName("tunnel"));
  EXPECT_EQ(Technology::kLoopback, Technology::CreateFromName("loopback"));
  EXPECT_EQ(Technology::kVPN, Technology::CreateFromName("vpn"));
  EXPECT_EQ(Technology::kPPP, Technology::CreateFromName("ppp"));
  EXPECT_EQ(Technology::kGuestInterface,
            Technology::CreateFromName("guest_interface"));
  EXPECT_EQ(Technology::kUnknown, Technology::CreateFromName("foo"));
  EXPECT_EQ(Technology::kUnknown, Technology::CreateFromName(""));
}

TEST(TechnologyTest, GetName) {
  EXPECT_EQ("ethernet", Technology(Technology::kEthernet).GetName());
  EXPECT_EQ("etherneteap", Technology(Technology::kEthernetEap).GetName());
  EXPECT_EQ("wifi", Technology(Technology::kWiFi).GetName());
  EXPECT_EQ("cellular", Technology(Technology::kCellular).GetName());
  EXPECT_EQ("tunnel", Technology(Technology::kTunnel).GetName());
  EXPECT_EQ("loopback", Technology(Technology::kLoopback).GetName());
  EXPECT_EQ("vpn", Technology(Technology::kVPN).GetName());
  EXPECT_EQ("ppp", Technology(Technology::kPPP).GetName());
  EXPECT_EQ("guest_interface",
            Technology(Technology::kGuestInterface).GetName());
  EXPECT_EQ("unknown", Technology(Technology::kUnknown).GetName());
}

TEST(TechnologyTest, CreateFromStorageGroup) {
  EXPECT_EQ(Technology::kVPN, Technology::CreateFromStorageGroup("vpn"));
  EXPECT_EQ(Technology::kVPN, Technology::CreateFromStorageGroup("vpn_a"));
  EXPECT_EQ(Technology::kVPN, Technology::CreateFromStorageGroup("vpn__a"));
  EXPECT_EQ(Technology::kVPN, Technology::CreateFromStorageGroup("vpn_a_1"));
  EXPECT_EQ(Technology::kUnknown, Technology::CreateFromStorageGroup("_vpn"));
  EXPECT_EQ(Technology::kUnknown, Technology::CreateFromStorageGroup("_"));
  EXPECT_EQ(Technology::kUnknown, Technology::CreateFromStorageGroup(""));
}

TEST(TechnologyTest, GetTechnologyVectorFromStringWithValidTechnologyNames) {
  std::vector<Technology> technologies;
  Error error;

  EXPECT_TRUE(GetTechnologyVectorFromString("", &technologies, &error));
  EXPECT_THAT(technologies, ElementsAre());
  EXPECT_TRUE(error.IsSuccess());

  EXPECT_TRUE(GetTechnologyVectorFromString("ethernet", &technologies, &error));
  EXPECT_THAT(technologies, ElementsAre(Technology::kEthernet));
  EXPECT_TRUE(error.IsSuccess());

  EXPECT_TRUE(
      GetTechnologyVectorFromString("ethernet,vpn", &technologies, &error));
  EXPECT_THAT(technologies,
              ElementsAre(Technology::kEthernet, Technology::kVPN));
  EXPECT_TRUE(error.IsSuccess());

  EXPECT_TRUE(GetTechnologyVectorFromString("wifi,ethernet,vpn", &technologies,
                                            &error));
  EXPECT_THAT(
      technologies,
      ElementsAre(Technology::kWiFi, Technology::kEthernet, Technology::kVPN));
  EXPECT_TRUE(error.IsSuccess());
}

TEST(TechnologyTest, GetTechnologyVectorFromStringWithInvalidTechnologyNames) {
  std::vector<Technology> technologies;
  Error error;

  EXPECT_FALSE(GetTechnologyVectorFromString("foo", &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("foo is an unknown technology name", error.message());

  EXPECT_FALSE(
      GetTechnologyVectorFromString("ethernet,bar", &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("bar is an unknown technology name", error.message());

  EXPECT_FALSE(
      GetTechnologyVectorFromString("ethernet,foo,vpn", &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("foo is an unknown technology name", error.message());
}

TEST(TechnologyTest,
     GetTechnologyVectorFromStringWithDuplicateTechnologyNames) {
  std::vector<Technology> technologies;
  Error error;

  EXPECT_FALSE(GetTechnologyVectorFromString("ethernet,vpn,ethernet",
                                             &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("ethernet is duplicated in the list", error.message());
}

}  // namespace shill
