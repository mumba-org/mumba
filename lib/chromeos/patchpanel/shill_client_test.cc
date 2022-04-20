// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/shill_client.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/fake_shill_client.h"

namespace patchpanel {
namespace {

class ShillClientTest : public testing::Test {
 protected:
  void SetUp() override {
    helper_ = std::make_unique<FakeShillClientHelper>();
    client_ = helper_->FakeClient();
    client_->RegisterDefaultLogicalDeviceChangedHandler(base::BindRepeating(
        &ShillClientTest::DefaultLogicalDeviceChangedHandler,
        base::Unretained(this)));
    client_->RegisterDefaultPhysicalDeviceChangedHandler(base::BindRepeating(
        &ShillClientTest::DefaultPhysicalDeviceChangedHandler,
        base::Unretained(this)));
    client_->RegisterDevicesChangedHandler(base::BindRepeating(
        &ShillClientTest::DevicesChangedHandler, base::Unretained(this)));
    client_->RegisterIPConfigsChangedHandler(base::BindRepeating(
        &ShillClientTest::IPConfigsChangedHandler, base::Unretained(this)));
    default_logical_ifname_.clear();
    added_.clear();
    removed_.clear();
  }

  void DefaultLogicalDeviceChangedHandler(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device) {
    default_logical_ifname_ = new_device.ifname;
  }

  void DefaultPhysicalDeviceChangedHandler(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device) {
    default_physical_ifname_ = new_device.ifname;
  }

  void DevicesChangedHandler(const std::vector<std::string>& added,
                             const std::vector<std::string>& removed) {
    added_ = added;
    removed_ = removed;
  }

  void IPConfigsChangedHandler(const std::string& device,
                               const ShillClient::IPConfig& ipconfig) {
    ipconfig_change_calls_.emplace_back(std::make_pair(device, ipconfig));
  }

 protected:
  std::string default_logical_ifname_;
  std::string default_physical_ifname_;
  std::vector<std::string> added_;
  std::vector<std::string> removed_;
  std::vector<std::pair<std::string, ShillClient::IPConfig>>
      ipconfig_change_calls_;
  std::unique_ptr<FakeShillClient> client_;
  std::unique_ptr<FakeShillClientHelper> helper_;
};

TEST_F(ShillClientTest, DevicesChangedHandlerCalledOnDevicesPropertyChange) {
  std::vector<dbus::ObjectPath> devices = {dbus::ObjectPath("/device/eth0"),
                                           dbus::ObjectPath("/device/wlan0")};
  auto value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->SetIfname("/device/eth0", "eth0");
  client_->SetIfname("/device/eth1", "eth1");
  client_->SetIfname("/device/wlan0", "wlan0");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(added_.size(), devices.size());
  EXPECT_NE(std::find(added_.begin(), added_.end(), "eth0"), added_.end());
  EXPECT_NE(std::find(added_.begin(), added_.end(), "wlan0"), added_.end());
  EXPECT_EQ(removed_.size(), 0);

  // Implies the default callback was run;
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");
  EXPECT_NE(std::find(added_.begin(), added_.end(), default_logical_ifname_),
            added_.end());

  devices.pop_back();
  devices.emplace_back(dbus::ObjectPath("/device/eth1"));
  value = brillo::Any(devices);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(added_.size(), 1);
  EXPECT_EQ(*added_.begin(), "eth1");
  EXPECT_EQ(removed_.size(), 1);
  EXPECT_EQ(*removed_.begin(), "wlan0");
}

TEST_F(ShillClientTest, VerifyDevicesPrefixStripped) {
  std::vector<dbus::ObjectPath> devices = {dbus::ObjectPath("/device/eth0")};
  auto value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->SetIfname("/device/eth0", "eth0");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(added_.size(), 1);
  EXPECT_EQ(*added_.begin(), "eth0");
  // Implies the default callback was run;
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");
}

TEST_F(ShillClientTest, DefaultDeviceChangedHandlerCalledOnNewDefaultDevice) {
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  client_->SetFakeDefaultLogicalDevice("wlan0");
  client_->SetFakeDefaultPhysicalDevice("wlan0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "wlan0");
  EXPECT_EQ(default_physical_ifname_, "wlan0");
}

TEST_F(ShillClientTest, DefaultDeviceChangedHandlerNotCalledForSameDefault) {
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  default_logical_ifname_.clear();
  default_physical_ifname_.clear();
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  // Implies the callback was not run the second time.
  EXPECT_EQ(default_logical_ifname_, "");
  EXPECT_EQ(default_physical_ifname_, "");
}

TEST_F(ShillClientTest, DefaultDeviceChanges) {
  // One network device appears.
  std::vector<dbus::ObjectPath> devices = {dbus::ObjectPath("/device/wlan0")};
  auto value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("wlan0");
  client_->SetFakeDefaultPhysicalDevice("wlan0");
  client_->SetIfname("/device/eth0", "eth0");
  client_->SetIfname("/device/wlan0", "wlan0");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(default_logical_ifname_, "wlan0");
  EXPECT_EQ(default_physical_ifname_, "wlan0");

  // A second device appears.
  default_logical_ifname_.clear();
  default_physical_ifname_.clear();
  devices = {dbus::ObjectPath("/device/eth0"),
             dbus::ObjectPath("/device/wlan0")};
  value = brillo::Any(devices);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(default_logical_ifname_, "");
  EXPECT_EQ(default_physical_ifname_, "");

  // The second device becomes the default interface.
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  // The first device disappears.
  devices = {dbus::ObjectPath("/device/eth0")};
  value = brillo::Any(devices);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  // The default device is still the same.
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  // All devices have disappeared.
  devices = {};
  value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("");
  client_->SetFakeDefaultPhysicalDevice("");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(default_logical_ifname_, "");
  EXPECT_EQ(default_physical_ifname_, "");
}

TEST_F(ShillClientTest, ListenToDeviceChangeSignalOnNewDevices) {
  // Adds a device.
  std::vector<dbus::ObjectPath> devices = {dbus::ObjectPath("/device/wlan0")};
  auto value = brillo::Any(devices);
  EXPECT_CALL(*helper_->mock_proxy(),
              DoConnectToSignal(shill::kFlimflamDeviceInterface,
                                shill::kMonitorPropertyChanged, _, _))
      .Times(1);
  client_->SetIfname("/device/eth0", "eth0");
  client_->SetIfname("/device/wlan0", "wlan0");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);

  // Adds another device. DoConnectToSignal() called only for the new added one.
  devices = {dbus::ObjectPath("/device/wlan0"),
             dbus::ObjectPath("/device/eth0")};
  value = brillo::Any(devices);
  EXPECT_CALL(*helper_->mock_proxy(),
              DoConnectToSignal(shill::kFlimflamDeviceInterface,
                                shill::kMonitorPropertyChanged, _, _))
      .Times(1);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
}

TEST_F(ShillClientTest, TriggerOnIPConfigsChangeHandlerOnce) {
  // Adds a device.
  std::vector<dbus::ObjectPath> devices = {dbus::ObjectPath("/device/wlan0")};
  auto devices_value = brillo::Any(devices);
  client_->SetIfname("/device/wlan0", "wlan0");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, devices_value);
  client_->NotifyDevicePropertyChange("wlan0", shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 1u);
  EXPECT_EQ(ipconfig_change_calls_.back().first, "wlan0");

  // Removes the device and adds it again.
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, brillo::Any());
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, devices_value);
  client_->NotifyDevicePropertyChange("wlan0", shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 2u);
  EXPECT_EQ(ipconfig_change_calls_.back().first, "wlan0");
}

}  // namespace
}  // namespace patchpanel
