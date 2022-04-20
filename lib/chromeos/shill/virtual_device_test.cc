// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/virtual_device.h"

#include <sys/socket.h>
#include <linux/if.h>  // NOLINT - Needs typedefs from sys/socket.h.

#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/store/fake_store.h"
#include "shill/technology.h"

using testing::_;
using testing::StrictMock;

namespace shill {

namespace {
const char kTestDeviceName[] = "tun0";
const int kTestInterfaceIndex = 5;
}  // namespace

class VirtualDeviceTest : public testing::Test {
 public:
  VirtualDeviceTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_(new VirtualDevice(&manager_,
                                  kTestDeviceName,
                                  kTestInterfaceIndex,
                                  Technology::kVPN)) {}

  ~VirtualDeviceTest() override = default;

  void SetUp() override { device_->rtnl_handler_ = &rtnl_handler_; }

 protected:
  MockControl control_;
  EventDispatcher dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  StrictMock<MockRTNLHandler> rtnl_handler_;

  VirtualDeviceRefPtr device_;
};

TEST_F(VirtualDeviceTest, technology) {
  EXPECT_EQ(Technology::kVPN, device_->technology());
  EXPECT_NE(Technology::kEthernet, device_->technology());
}

TEST_F(VirtualDeviceTest, Load) {
  FakeStore storage;
  EXPECT_TRUE(device_->Load(&storage));
}

TEST_F(VirtualDeviceTest, Save) {
  FakeStore storage;
  EXPECT_TRUE(device_->Save(&storage));
  EXPECT_TRUE(storage.GetGroups().empty());
}

TEST_F(VirtualDeviceTest, Start) {
  Error error(Error::kOperationInitiated);
  EXPECT_CALL(rtnl_handler_, SetInterfaceFlags(_, IFF_UP, IFF_UP));
  device_->Start(&error, EnabledStateChangedCallback());
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(VirtualDeviceTest, Stop) {
  Error error(Error::kOperationInitiated);
  device_->Stop(&error, EnabledStateChangedCallback());
  EXPECT_TRUE(error.IsSuccess());
}

// TODO(quiche): Add test for UpdateIPConfig. crbug.com/266404

}  // namespace shill
