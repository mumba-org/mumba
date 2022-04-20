// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MOCK_DATAPATH_H_
#define PATCHPANEL_MOCK_DATAPATH_H_

#include <string>
#include <vector>

#include "patchpanel/datapath.h"

namespace patchpanel {

// ARC networking data path configuration utility.
class MockDatapath : public Datapath {
 public:
  explicit MockDatapath() : Datapath(nullptr, nullptr, nullptr) {}
  MockDatapath(const MockDatapath&) = delete;
  MockDatapath& operator=(const MockDatapath&) = delete;

  ~MockDatapath() = default;

  MOCK_METHOD0(Start, void());
  MOCK_METHOD0(Stop, void());
  MOCK_METHOD2(NetnsAttachName,
               bool(const std::string& netns_name, pid_t netns_pid));
  MOCK_METHOD1(NetnsDeleteName, bool(const std::string& netns_name));

  MOCK_METHOD3(AddBridge,
               bool(const std::string& ifname,
                    uint32_t ipv4_addr,
                    uint32_t prefix_len));
  MOCK_METHOD1(RemoveBridge, void(const std::string& ifname));
  MOCK_METHOD2(AddToBridge,
               bool(const std::string& br_ifname, const std::string& ifname));

  MOCK_METHOD4(AddTAP,
               std::string(const std::string& name,
                           const MacAddress* mac_addr,
                           const SubnetAddress* ipv4_addr,
                           const std::string& user));
  MOCK_METHOD8(ConnectVethPair,
               bool(pid_t pid,
                    const std::string& netns_name,
                    const std::string& veth_ifname,
                    const std::string& peer_ifname,
                    const MacAddress& remote_mac_addr,
                    uint32_t remote_ipv4_addr,
                    uint32_t remote_ipv4_prefix_len,
                    bool remote_multicast_flag));
  MOCK_METHOD1(RemoveInterface, void(const std::string& ifname));
  MOCK_METHOD6(StartRoutingDevice,
               void(const std::string& ext_ifname,
                    const std::string& int_ifname,
                    uint32_t int_ipv4_addr,
                    TrafficSource source,
                    bool route_on_vpn,
                    uint32_t peer_ipv4_addr));
  MOCK_METHOD5(StopRoutingDevice,
               void(const std::string& ext_ifname,
                    const std::string& int_ifname,
                    uint32_t int_ipv4_addr,
                    TrafficSource source,
                    bool route_on_vpn));
  MOCK_METHOD3(MaskInterfaceFlags,
               bool(const std::string& ifname, uint16_t on, uint16_t off));
  MOCK_METHOD3(AddIPv4Route, bool(uint32_t gw, uint32_t dst, uint32_t netmask));
  MOCK_METHOD1(SetConntrackHelpers, bool(const bool enable_helpers));
  MOCK_METHOD2(SetRouteLocalnet,
               bool(const std::string& ifname, const bool enable));
  MOCK_METHOD2(DumpIptables,
               std::string(IpFamily family, const std::string& table));
  MOCK_METHOD1(ModprobeAll, bool(const std::vector<std::string>& modules));
  MOCK_METHOD2(AddInboundIPv4DNAT,
               void(const std::string& ifname, const std::string& ipv4_addr));
  MOCK_METHOD2(RemoveInboundIPv4DNAT,
               void(const std::string& ifname, const std::string& ipv4_addr));
  MOCK_METHOD1(AddAdbPortAccessRule, bool(const std::string& ifname));
  MOCK_METHOD1(DeleteAdbPortAccessRule, void(const std::string& ifname));
  MOCK_METHOD5(ModifyChain,
               bool(IpFamily family,
                    const std::string& table,
                    const std::string& op,
                    const std::string& chain,
                    bool log_failures));
  MOCK_METHOD4(ModifyIptables,
               bool(IpFamily family,
                    const std::string& table,
                    const std::vector<std::string>& argv,
                    bool log_failures));
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MOCK_DATAPATH_H_
