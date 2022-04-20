// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/arc_service.h"

#include <net/if.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/guest_type.h"
#include "patchpanel/mock_datapath.h"
#include "patchpanel/net_util.h"

using testing::_;
using testing::AnyNumber;
using testing::Eq;
using testing::Invoke;
using testing::Mock;
using testing::Pair;
using testing::Pointee;
using testing::Return;
using testing::ReturnRef;
using testing::StrEq;
using testing::UnorderedElementsAre;

namespace patchpanel {
namespace {
constexpr pid_t kTestPID = -2;
constexpr uint32_t kTestCID = 2;
constexpr uint32_t kArcHostIP = Ipv4Addr(100, 115, 92, 1);
constexpr uint32_t kArcGuestIP = Ipv4Addr(100, 115, 92, 2);
constexpr uint32_t kFirstEthHostIP = Ipv4Addr(100, 115, 92, 5);
constexpr uint32_t kFirstEthGuestIP = Ipv4Addr(100, 115, 92, 6);
constexpr uint32_t kSecondEthHostIP = Ipv4Addr(100, 115, 92, 9);
constexpr uint32_t kFirstWifiHostIP = Ipv4Addr(100, 115, 92, 13);
constexpr uint32_t kSecondWifiHostIP = Ipv4Addr(100, 115, 92, 17);
constexpr uint32_t kFirstCellHostIP = Ipv4Addr(100, 115, 92, 21);
constexpr MacAddress kArcVmArc0MacAddr = {0x42, 0x37, 0x05, 0x13, 0x17, 0x01};

}  // namespace

class ArcServiceTest : public testing::Test {
 public:
  ArcServiceTest() : testing::Test() {}

 protected:
  void SetUp() override {
    datapath_ = std::make_unique<MockDatapath>();
    addr_mgr_ = std::make_unique<AddressManager>();
    metrics_ = std::make_unique<MetricsLibraryMock>();
    guest_devices_.clear();
  }

  std::unique_ptr<ArcService> NewService(GuestMessage::GuestType guest) {
    return std::make_unique<ArcService>(
        datapath_.get(), addr_mgr_.get(), guest, metrics_.get(),
        base::BindRepeating(&ArcServiceTest::DeviceHandler,
                            base::Unretained(this)));
  }

  void DeviceHandler(const Device& device,
                     Device::ChangeEvent event,
                     GuestMessage::GuestType guest_type) {
    guest_devices_[device.host_ifname()] = event;
  }

  std::unique_ptr<AddressManager> addr_mgr_;
  std::unique_ptr<MockDatapath> datapath_;
  std::unique_ptr<MetricsLibraryMock> metrics_;
  std::map<std::string, Device::ChangeEvent> guest_devices_;
};

TEST_F(ArcServiceTest, NotStarted_AddDevice) {
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), _, _)).Times(0);
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             _, _, false, _))
      .Times(0);
  EXPECT_CALL(*datapath_, AddInboundIPv4DNAT(StrEq("eth0"), _)).Times(0);

  auto svc = NewService(GuestMessage::ARC);
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  EXPECT_TRUE(svc->devices_.find("eth0") == svc->devices_.end());
  EXPECT_FALSE(svc->shill_devices_.find("eth0") == svc->shill_devices_.end());
}

TEST_F(ArcServiceTest, NotStarted_AddRemoveDevice) {
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), _, _)).Times(0);
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             _, _, false, _))
      .Times(0);
  EXPECT_CALL(*datapath_, AddInboundIPv4DNAT(StrEq("eth0"), _)).Times(0);
  EXPECT_CALL(*datapath_,
              StopRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"), _, _, false))
      .Times(0);
  EXPECT_CALL(*datapath_, RemoveInboundIPv4DNAT(StrEq("eth0"), _)).Times(0);
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arc_eth0"))).Times(0);

  auto svc = NewService(GuestMessage::ARC);
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->RemoveDevice("eth0");
  EXPECT_TRUE(svc->devices_.find("eth0") == svc->devices_.end());
  EXPECT_TRUE(svc->shill_devices_.find("eth0") == svc->shill_devices_.end());
}

TEST_F(ArcServiceTest, VerifyAddrConfigs) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth1"), kSecondEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_wlan0"), kFirstWifiHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_wlan1"), kSecondWifiHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_wwan0"), kFirstCellHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), _, _, _, _, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->AddDevice("eth1", ShillClient::Device::Type::kEthernet);
  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  svc->AddDevice("wlan1", ShillClient::Device::Type::kWifi);
  svc->AddDevice("wwan0", ShillClient::Device::Type::kCellular);
}

TEST_F(ArcServiceTest, VerifyAddrOrder) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_wlan0"), kFirstWifiHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), _, _, _, _, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->RemoveDevice("eth0");
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
}

TEST_F(ArcServiceTest, StableArcVmMacAddrs) {
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillRepeatedly(Return("vmtap"));
  EXPECT_CALL(*datapath_, AddBridge(_, _, 30)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestCID);
  auto configs = svc->GetDeviceConfigs();
  EXPECT_EQ(configs.size(), 6);
  auto mac_addr = kArcVmArc0MacAddr;
  for (const auto* config : configs) {
    EXPECT_EQ(config->mac_addr(), mac_addr);
    mac_addr[5]++;
  }
}

// ContainerImpl

TEST_F(ArcServiceTest, ContainerImpl_Start) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());

  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_FailsToCreateInterface) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(false));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30)).Times(0);
  EXPECT_CALL(*datapath_, RemoveBridge(_)).Times(0);
  EXPECT_CALL(*datapath_, SetConntrackHelpers(_)).Times(0);

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_FALSE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_FailsToAddInterfaceToBridge) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(false));
  EXPECT_CALL(*datapath_, RemoveInterface(_)).Times(0);
  EXPECT_CALL(*datapath_, RemoveBridge(_)).Times(0);
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).Times(0);

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_OnStartDevice) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  // Expectations for arc0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetheth0"),
                              StrEq("eth0"), _, kFirstEthGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vetheth0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             kFirstEthGuestIP,
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_GetDevices) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  // Expectations for arc0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  EXPECT_CALL(*datapath_, NetnsAttachName(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, ConnectVethPair(_, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(_, _, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  Mock::VerifyAndClearExpectations(datapath_.get());

  const auto devs = svc->GetDevices();
  EXPECT_EQ(devs.size(), 2);

  const auto it1 = std::find_if(
      devs.begin(), devs.end(),
      [](const Device* dev) { return dev->phys_ifname() == "eth0"; });
  EXPECT_NE(it1, devs.end());
  EXPECT_EQ((*it1)->host_ifname(), "arc_eth0");
  EXPECT_EQ((*it1)->guest_ifname(), "eth0");
  EXPECT_EQ((*it1)->type(), GuestType::ARC_NET);

  const auto it2 = std::find_if(
      devs.begin(), devs.end(),
      [](const Device* dev) { return dev->phys_ifname() == "wlan0"; });
  EXPECT_NE(it2, devs.end());
  EXPECT_EQ((*it2)->host_ifname(), "arc_wlan0");
  EXPECT_EQ((*it2)->guest_ifname(), "wlan0");
  EXPECT_EQ((*it2)->type(), GuestType::ARC_NET);
}

TEST_F(ArcServiceTest, ContainerImpl_DeviceHandler) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  // Expectations for arc0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  EXPECT_CALL(*datapath_, AddBridge(_, _, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, ConnectVethPair(_, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(true));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  EXPECT_EQ(guest_devices_.size(), 2);
  EXPECT_THAT(guest_devices_,
              UnorderedElementsAre(
                  Pair(StrEq("arc_eth0"), Device::ChangeEvent::ADDED),
                  Pair(StrEq("arc_wlan0"), Device::ChangeEvent::ADDED)));
  guest_devices_.clear();

  svc->RemoveDevice("wlan0");
  EXPECT_THAT(guest_devices_,
              UnorderedElementsAre(
                  Pair(StrEq("arc_wlan0"), Device::ChangeEvent::REMOVED)));
  guest_devices_.clear();

  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  EXPECT_THAT(guest_devices_,
              UnorderedElementsAre(
                  Pair(StrEq("arc_wlan0"), Device::ChangeEvent::ADDED)));
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_StartAfterDevice) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  // Expectations for arc0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetheth0"),
                              StrEq("eth0"), _, kFirstEthGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vetheth0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             kFirstEthGuestIP,
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));

  auto svc = NewService(GuestMessage::ARC);
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_Stop) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  // Expectations for arc0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetheth0"),
                              StrEq("eth0"), _, kFirstEthGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vetheth0")))
      .WillOnce(Return(true));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for arc0 teardown.
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetharc0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arcbr0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetheth0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arc_eth0"))).Times(1);
  EXPECT_CALL(*datapath_, SetConntrackHelpers(false)).WillOnce(Return(true));
  EXPECT_CALL(*datapath_, NetnsDeleteName(StrEq("arc_netns")))
      .WillOnce(Return(true));

  svc->Stop(kTestPID);
  EXPECT_FALSE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_OnStopDevice) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  // Expectations for arc0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetheth0"),
                              StrEq("eth0"), _, kFirstEthGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vetheth0")))
      .WillOnce(Return(true));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 teardown.
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetheth0"))).Times(1);
  EXPECT_CALL(*datapath_, StopRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                            Ipv4Addr(100, 115, 92, 6),
                                            TrafficSource::ARC, false));
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arc_eth0"))).Times(1);

  svc->RemoveDevice("eth0");
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, ContainerImpl_Restart) {
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  auto svc = NewService(GuestMessage::ARC);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetheth0"),
                              StrEq("eth0"), _, kFirstEthGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vetheth0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             kFirstEthGuestIP,
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for arc0, eth0, and arc netns teardown.
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetharc0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arcbr0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetheth0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arc_eth0"))).Times(1);
  EXPECT_CALL(*datapath_, SetConntrackHelpers(false)).WillOnce(Return(true));
  EXPECT_CALL(*datapath_, NetnsDeleteName(StrEq("arc_netns")))
      .WillOnce(Return(true));
  svc->Stop(kTestPID);
  EXPECT_FALSE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for arc0, eth0, and arc netns setup on restart.
  EXPECT_CALL(*datapath_, NetnsAttachName(StrEq("arc_netns"), kTestPID))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetharc0"),
                              StrEq("arc0"), _, kArcGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vetharc0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              ConnectVethPair(kTestPID, StrEq("arc_netns"), StrEq("vetheth0"),
                              StrEq("eth0"), _, kFirstEthGuestIP, 30, false))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vetheth0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             kFirstEthGuestIP,
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

// VM Impl

TEST_F(ArcServiceTest, VmImpl_Start) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_StartDevice) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vmtap1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             Ipv4Addr(100, 115, 92, 6),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_StartMultipleDevices) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vmtap1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             Ipv4Addr(100, 115, 92, 6),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for wlan0 setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_wlan0"), kFirstWifiHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_wlan0"), StrEq("vmtap3")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("wlan0"), StrEq("arc_wlan0"),
                                             Ipv4Addr(100, 115, 92, 14),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("wlan0"), StrEq("100.115.92.14")));

  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth1 setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth1"), kSecondEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth1"), StrEq("vmtap2")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth1"), StrEq("arc_eth1"),
                                             Ipv4Addr(100, 115, 92, 10),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth1"), StrEq("100.115.92.10")));

  svc->AddDevice("eth1", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_Stop) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for "arc0" teardown.
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arcbr0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetharc0"))).Times(0);
  // Expectations for tap devices teardown
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap0")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap1")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap2")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap3")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap4")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap5")));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(false)).WillOnce(Return(true));

  svc->Stop(kTestPID);
  EXPECT_FALSE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_Restart) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));
  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vmtap1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             Ipv4Addr(100, 115, 92, 6),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for arc0, eth0, and tap devices teardown.
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arcbr0"))).Times(1);
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vetharc0"))).Times(0);
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap0")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap1")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap2")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap3")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap4")));
  EXPECT_CALL(*datapath_, RemoveInterface(StrEq("vmtap5")));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(false)).WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StopRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                            Ipv4Addr(100, 115, 92, 6),
                                            TrafficSource::ARC, false));
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arc_eth0")));
  svc->Stop(kTestPID);
  EXPECT_FALSE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for arc0, eth0, and tap device pre-creation on restart.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vmtap1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             Ipv4Addr(100, 115, 92, 6),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_StopDevice) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  // Expectations for "arc0" setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 setup.
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arc_eth0"), kFirstEthHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arc_eth0"), StrEq("vmtap1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, StartRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                             Ipv4Addr(100, 115, 92, 6),
                                             TrafficSource::ARC, false, _));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Expectations for eth0 teardown.
  EXPECT_CALL(*datapath_, StopRoutingDevice(StrEq("eth0"), StrEq("arc_eth0"),
                                            Ipv4Addr(100, 115, 92, 6),
                                            TrafficSource::ARC, false));
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(StrEq("eth0"), StrEq("100.115.92.6")));
  EXPECT_CALL(*datapath_, RemoveBridge(StrEq("arc_eth0")));

  svc->RemoveDevice("eth0");
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_GetDevices) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  Mock::VerifyAndClearExpectations(datapath_.get());

  EXPECT_CALL(*datapath_, AddBridge(_, _, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  svc->AddDevice("eth1", ShillClient::Device::Type::kEthernet);
  Mock::VerifyAndClearExpectations(datapath_.get());

  const auto devs = svc->GetDevices();
  EXPECT_EQ(devs.size(), 3);

  const auto it1 = std::find_if(
      devs.begin(), devs.end(),
      [](const Device* dev) { return dev->phys_ifname() == "eth0"; });
  EXPECT_NE(it1, devs.end());
  EXPECT_EQ((*it1)->host_ifname(), "arc_eth0");
  EXPECT_EQ((*it1)->guest_ifname(), "eth1");
  EXPECT_EQ((*it1)->type(), GuestType::ARC_NET);

  const auto it2 = std::find_if(
      devs.begin(), devs.end(),
      [](const Device* dev) { return dev->phys_ifname() == "wlan0"; });
  EXPECT_NE(it2, devs.end());
  EXPECT_EQ((*it2)->host_ifname(), "arc_wlan0");
  EXPECT_EQ((*it2)->guest_ifname(), "eth3");
  EXPECT_EQ((*it2)->type(), GuestType::ARC_NET);

  const auto it3 = std::find_if(
      devs.begin(), devs.end(),
      [](const Device* dev) { return dev->phys_ifname() == "eth1"; });
  EXPECT_NE(it3, devs.end());
  EXPECT_EQ((*it3)->host_ifname(), "arc_eth1");
  EXPECT_EQ((*it3)->guest_ifname(), "eth2");
  EXPECT_EQ((*it3)->type(), GuestType::ARC_NET);
}

TEST_F(ArcServiceTest, VmImpl_DeviceHandler) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"));
  EXPECT_CALL(*datapath_, AddBridge(StrEq("arcbr0"), kArcHostIP, 30))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(StrEq("arcbr0"), StrEq("vmtap0")))
      .WillOnce(Return(true));
  EXPECT_CALL(*datapath_, SetConntrackHelpers(true)).WillOnce(Return(true));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);
  EXPECT_TRUE(svc->IsStarted());
  Mock::VerifyAndClearExpectations(datapath_.get());

  EXPECT_CALL(*datapath_, AddBridge(_, _, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddToBridge(_, _)).WillRepeatedly(Return(true));

  svc->AddDevice("eth0", ShillClient::Device::Type::kEthernet);
  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  EXPECT_EQ(guest_devices_.size(), 2);
  EXPECT_THAT(guest_devices_,
              UnorderedElementsAre(
                  Pair(StrEq("arc_eth0"), Device::ChangeEvent::ADDED),
                  Pair(StrEq("arc_wlan0"), Device::ChangeEvent::ADDED)));
  guest_devices_.clear();

  svc->RemoveDevice("wlan0");
  EXPECT_THAT(guest_devices_,
              UnorderedElementsAre(
                  Pair(StrEq("arc_wlan0"), Device::ChangeEvent::REMOVED)));
  guest_devices_.clear();

  svc->AddDevice("wlan0", ShillClient::Device::Type::kWifi);
  EXPECT_THAT(guest_devices_,
              UnorderedElementsAre(
                  Pair(StrEq("arc_wlan0"), Device::ChangeEvent::ADDED)));
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(ArcServiceTest, VmImpl_ArcvmInterfaceMapping) {
  // Expectations for tap devices pre-creation.
  EXPECT_CALL(*datapath_, AddTAP(StrEq(""), _, nullptr, StrEq("crosvm")))
      .WillOnce(Return("vmtap2"))
      .WillOnce(Return("vmtap3"))
      .WillOnce(Return("vmtap4"))
      .WillOnce(Return("vmtap5"))
      .WillOnce(Return("vmtap6"))
      .WillOnce(Return("vmtap8"));

  auto svc = NewService(GuestMessage::ARC_VM);
  svc->Start(kTestPID);

  std::map<std::string, std::string> arcvm_guest_ifnames = {
      {"vmtap2", "eth0"}, {"vmtap3", "eth1"}, {"vmtap4", "eth2"},
      {"vmtap5", "eth3"}, {"vmtap6", "eth4"}, {"vmtap8", "eth5"},
  };

  for (const auto& [tap, arcvm_ifname] : arcvm_guest_ifnames) {
    auto it = svc->arcvm_guest_ifnames_.find(tap);
    EXPECT_TRUE(it != svc->arcvm_guest_ifnames_.end());
    EXPECT_EQ(it->second, arcvm_ifname);
  }
}

}  // namespace patchpanel
