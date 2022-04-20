// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/apn_list.h"

#include <gtest/gtest.h>

#include <base/containers/contains.h>
#include <chromeos/dbus/service_constants.h>

using testing::Test;

namespace shill {

TEST(ApnListTest, AddApn) {
  std::vector<MobileOperatorInfo::MobileAPN> mobile_apns;
  MobileOperatorInfo::MobileAPN mobile_apn1;
  mobile_apn1.apn = "apn1";
  mobile_apn1.ip_type = "IPV4";
  mobile_apn1.is_attach_apn = true;
  mobile_apn1.username = "user1";
  mobile_apn1.password = "pass1";
  mobile_apn1.authentication = "PAP";

  MobileOperatorInfo::MobileAPN mobile_apn2;
  mobile_apn2.apn = "apn2";
  mobile_apn2.ip_type = "IPV4V6";
  mobile_apn2.is_attach_apn = false;
  mobile_apn2.username = "user2";
  mobile_apn2.password = "pass2";
  mobile_apn2.authentication = "CHAP";

  mobile_apns.push_back(mobile_apn1);
  mobile_apns.push_back(mobile_apn2);
  ApnList apn_list;
  apn_list.AddApns(mobile_apns, ApnList::ApnSource::kModem);

  Stringmaps apns = apn_list.GetList();
  ASSERT_EQ(apns.size(), 2);

  Stringmap* apn = &apns.at(0);

  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn1");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4");
  EXPECT_TRUE(base::Contains(*apn, kApnAttachProperty));
  EXPECT_STREQ(apn->at(kApnAttachProperty).c_str(), kApnAttachProperty);
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user1");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass1");
  EXPECT_STREQ(apn->at(cellular::kApnSource).c_str(),
               cellular::kApnSourceModem);

  apn = &apns.at(1);
  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn2");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4V6");
  EXPECT_FALSE(base::Contains(*apn, kApnAttachProperty));
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user2");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass2");
  EXPECT_STREQ(apn->at(cellular::kApnSource).c_str(),
               cellular::kApnSourceModem);

  std::vector<MobileOperatorInfo::MobileAPN> mobile_apns2;
  mobile_apns2.push_back(mobile_apn1);

  // This should update the first entry.
  apn_list.AddApns(mobile_apns2, ApnList::ApnSource::kModb);
  apns = apn_list.GetList();
  ASSERT_EQ(apns.size(), 2);
  apn = &apns.at(0);
  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn1");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4");
  EXPECT_TRUE(base::Contains(*apn, kApnAttachProperty));
  EXPECT_STREQ(apn->at(kApnAttachProperty).c_str(), kApnAttachProperty);
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user1");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass1");
  EXPECT_STREQ(apn->at(cellular::kApnSource).c_str(), cellular::kApnSourceMoDb);
}

}  // namespace shill
