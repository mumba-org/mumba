// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ppp_device.h"

#include <map>
#include <string>

#include <gtest/gtest.h>

#include "shill/metrics.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"

namespace shill {

// TODO(quiche): Add test for UpdateIPConfigFromPPP. crbug.com/266404

TEST(PPPDeviceTest, GetInterfaceName) {
  std::map<std::string, std::string> config;
  config[kPPPInterfaceName] = "ppp0";
  config["foo"] = "bar";
  EXPECT_EQ("ppp0", PPPDevice::GetInterfaceName(config));
}

TEST(PPPDeviceTest, ParseIPConfiguration) {
  MockControl control;
  MockMetrics metrics;
  MockManager manager(&control, nullptr, &metrics);
  scoped_refptr<PPPDevice> device = new PPPDevice(&manager, "test0", 0);

  std::map<std::string, std::string> config;
  config[kPPPInternalIP4Address] = "4.5.6.7";
  config[kPPPExternalIP4Address] = "33.44.55.66";
  config[kPPPGatewayAddress] = "192.168.1.1";
  config[kPPPDNS1] = "1.1.1.1";
  config[kPPPDNS2] = "2.2.2.2";
  config[kPPPInterfaceName] = "ppp0";
  config[kPPPLNSAddress] = "99.88.77.66";
  config[kPPPMRU] = "1492";
  config["foo"] = "bar";  // Unrecognized keys don't cause crash.
  IPConfig::Properties props = device->ParseIPConfiguration(config);
  EXPECT_EQ(IPAddress::kFamilyIPv4, props.address_family);
  EXPECT_EQ(IPAddress::GetMaxPrefixLength(IPAddress::kFamilyIPv4),
            props.subnet_prefix);
  EXPECT_EQ("4.5.6.7", props.address);
  EXPECT_EQ("33.44.55.66", props.peer_address);
  EXPECT_EQ("192.168.1.1", props.gateway);
  ASSERT_EQ(2, props.dns_servers.size());
  EXPECT_EQ("1.1.1.1", props.dns_servers[0]);
  EXPECT_EQ("2.2.2.2", props.dns_servers[1]);
  EXPECT_EQ("99.88.77.66/32", props.exclusion_list[0]);
  EXPECT_EQ(1, props.exclusion_list.size());
  EXPECT_EQ(1492, props.mtu);

  // No gateway specified.
  config.erase(kPPPGatewayAddress);
  IPConfig::Properties props2 = device->ParseIPConfiguration(config);
  EXPECT_EQ("33.44.55.66", props2.gateway);
}

}  // namespace shill
