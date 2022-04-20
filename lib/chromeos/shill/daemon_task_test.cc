// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/rtnetlink.h>
#include <stdint.h>

#include <string>
#include <vector>

#include <base/bind.h>
#include <base/memory/ref_counted.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/daemon_task.h"
#include "shill/logging.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_process_manager.h"
#include "shill/mock_routing_table.h"
#include "shill/net/io_handler.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/net/ndisc.h"
#include "shill/network/mock_dhcp_provider.h"
#include "shill/shill_test_config.h"
#include "shill/test_event_dispatcher.h"

#if !defined(DISABLE_WIFI)
#include "shill/net/mock_netlink_manager.h"
#include "shill/net/nl80211_message.h"
#endif  // !defined(DISABLE_WIFI)

using ::testing::_;
using ::testing::Expectation;
using ::testing::Mock;
using ::testing::Return;
using ::testing::Test;

namespace shill {

class DaemonTaskForTest : public DaemonTask {
 public:
  DaemonTaskForTest(const Settings& setttings, Config* config)
      : DaemonTask(Settings(), config) {}
  ~DaemonTaskForTest() override = default;

  bool quit_result() const { return quit_result_; }

  void RunMessageLoop() { dispatcher_->DispatchForever(); }

  bool Quit(const base::Closure& completion_callback) override {
    quit_result_ = DaemonTask::Quit(completion_callback);
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&EventDispatcher::QuitDispatchForever,
                       // dispatcher_ will not be deleted before RunLoop quits.
                       base::Unretained(dispatcher_.get())));
    return quit_result_;
  }

 private:
  bool quit_result_;
};

class DaemonTaskTest : public Test {
 public:
  DaemonTaskTest()
      : daemon_(DaemonTask::Settings(), &config_),
        dispatcher_(new EventDispatcherForTest()),
        control_(new MockControl()),
        metrics_(new MockMetrics()),
        manager_(new MockManager(control_, dispatcher_, metrics_)),
        device_info_(manager_) {}
  ~DaemonTaskTest() override = default;
  void SetUp() override {
    // Tests initialization done by the daemon's constructor
    daemon_.rtnl_handler_ = &rtnl_handler_;
    daemon_.routing_table_ = &routing_table_;
    daemon_.dhcp_provider_ = &dhcp_provider_;
    daemon_.process_manager_ = &process_manager_;
    daemon_.metrics_.reset(metrics_);        // Passes ownership
    daemon_.manager_.reset(manager_);        // Passes ownership
    daemon_.control_.reset(control_);        // Passes ownership
    daemon_.dispatcher_.reset(dispatcher_);  // Passes ownership

#if !defined(DISABLE_WIFI)
    daemon_.netlink_manager_ = &netlink_manager_;
#endif  // !defined(DISABLE_WIFI)
  }
  void StartDaemon() { daemon_.Start(); }

  void StopDaemon() { daemon_.Stop(); }

  void RunDaemon() { daemon_.RunMessageLoop(); }

  void ApplySettings(const DaemonTask::Settings& settings) {
    daemon_.settings_ = settings;
    daemon_.ApplySettings();
  }

  MOCK_METHOD(void, TerminationAction, ());
  MOCK_METHOD(void, BreakTerminationLoop, ());

 protected:
  TestConfig config_;
  DaemonTaskForTest daemon_;
  MockRTNLHandler rtnl_handler_;
  MockRoutingTable routing_table_;
  MockDHCPProvider dhcp_provider_;
  MockProcessManager process_manager_;
  EventDispatcherForTest* dispatcher_;
  MockControl* control_;
  MockMetrics* metrics_;
  MockManager* manager_;
#if !defined(DISABLE_WIFI)
  MockNetlinkManager netlink_manager_;
#endif  // !defined(DISABLE_WIFI)
  DeviceInfo device_info_;
};

TEST_F(DaemonTaskTest, StartStop) {
  // To ensure we do not have any stale routes, we flush a device's routes
  // when it is started.  This requires that the routing table is fully
  // populated before we create and start devices.  So test to make sure that
  // the RoutingTable starts before the Manager (which in turn starts
  // DeviceInfo who is responsible for creating and starting devices).
  // The result is that we request the dump of the routing table and when that
  // completes, we request the dump of the links.  For each link found, we
  // create and start the device.
  EXPECT_CALL(rtnl_handler_, Start(RTMGRP_LINK | RTMGRP_IPV4_IFADDR |
                                   RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR |
                                   RTMGRP_IPV6_ROUTE | RTMGRP_ND_USEROPT));
  Expectation routing_table_started = EXPECT_CALL(routing_table_, Start());
  EXPECT_CALL(dhcp_provider_, Init(_, _, _));
  EXPECT_CALL(process_manager_, Init(_));
#if !defined(DISABLE_WIFI)
  EXPECT_CALL(netlink_manager_, Init());
  const uint16_t kNl80211MessageType = 42;  // Arbitrary.
  EXPECT_CALL(netlink_manager_,
              GetFamily(Nl80211Message::kMessageTypeString, _))
      .WillOnce(Return(kNl80211MessageType));
  EXPECT_CALL(netlink_manager_, Start());
#endif  // !defined(DISABLE_WIFI)
  EXPECT_CALL(*manager_, Start()).After(routing_table_started);
  StartDaemon();
  Mock::VerifyAndClearExpectations(manager_);

  EXPECT_CALL(*manager_, Stop());
  EXPECT_CALL(process_manager_, Stop());
  StopDaemon();
}

ACTION_P2(CompleteAction, manager, name) {
  manager->TerminationActionComplete(name);
}

TEST_F(DaemonTaskTest, QuitWithTerminationAction) {
  // This expectation verifies that the termination actions are invoked.
  EXPECT_CALL(*this, TerminationAction())
      .WillOnce(CompleteAction(manager_, "daemon test"));
  EXPECT_CALL(*this, BreakTerminationLoop()).Times(1);

  manager_->AddTerminationAction(
      "daemon test",
      base::Bind(&DaemonTaskTest::TerminationAction, base::Unretained(this)));

  // Run Daemon::Quit() after the daemon starts running.
  dispatcher_->PostTask(
      FROM_HERE,
      base::Bind(IgnoreResult(&DaemonTask::Quit), base::Unretained(&daemon_),
                 base::Bind(&DaemonTaskTest::BreakTerminationLoop,
                            base::Unretained(this))));

  RunDaemon();
  EXPECT_FALSE(daemon_.quit_result());
}

TEST_F(DaemonTaskTest, QuitWithoutTerminationActions) {
  EXPECT_CALL(*this, BreakTerminationLoop()).Times(0);
  EXPECT_TRUE(daemon_.Quit(base::Bind(&DaemonTaskTest::BreakTerminationLoop,
                                      base::Unretained(this))));
}

TEST_F(DaemonTaskTest, ApplySettings) {
  DaemonTask::Settings settings;
  std::vector<std::string> kEmptyStringList;
  EXPECT_CALL(*manager_, SetBlockedDevices(kEmptyStringList));
  EXPECT_CALL(*manager_, SetTechnologyOrder("", _));
  EXPECT_CALL(*manager_, SetIgnoreUnknownEthernet(false));
  EXPECT_CALL(*manager_, SetStartupPortalList(_)).Times(0);
  EXPECT_CALL(*manager_, SetPassiveMode()).Times(0);
  EXPECT_CALL(*manager_, SetMinimumMTU(_)).Times(0);
  EXPECT_CALL(*manager_, SetAcceptHostnameFrom(""));
  ApplySettings(settings);
  Mock::VerifyAndClearExpectations(manager_);

  std::vector<std::string> kBlockedDevices = {"eth0", "eth1"};
  settings.devices_blocked = kBlockedDevices;
  settings.default_technology_order = "wifi,ethernet";
  settings.ignore_unknown_ethernet = false;
  settings.portal_list = "cellular";
  settings.use_portal_list = true;
  settings.passive_mode = true;
  settings.minimum_mtu = 256;
  settings.accept_hostname_from = "eth*";
  EXPECT_CALL(*manager_, SetBlockedDevices(kBlockedDevices));
  EXPECT_CALL(*manager_, SetTechnologyOrder("wifi,ethernet", _));
  EXPECT_CALL(*manager_, SetIgnoreUnknownEthernet(false));
  EXPECT_CALL(*manager_, SetStartupPortalList("cellular"));
  EXPECT_CALL(*manager_, SetPassiveMode());
  EXPECT_CALL(*manager_, SetMinimumMTU(256));
  EXPECT_CALL(*manager_, SetAcceptHostnameFrom("eth*"));
  ApplySettings(settings);
  Mock::VerifyAndClearExpectations(manager_);
}

}  // namespace shill
