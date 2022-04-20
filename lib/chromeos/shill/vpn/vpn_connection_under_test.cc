// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_connection_under_test.h"

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/ipconfig.h"
#include "shill/service.h"

namespace shill {

VPNConnectionUnderTest::VPNConnectionUnderTest(
    std::unique_ptr<Callbacks> callbacks, EventDispatcher* dispatcher)
    : VPNConnection(std::move(callbacks), dispatcher) {}

void VPNConnectionUnderTest::TriggerConnected(
    const std::string& link_name,
    int interface_index,
    const IPConfig::Properties& ip_properties) {
  NotifyConnected(link_name, interface_index, ip_properties);
}

void VPNConnectionUnderTest::TriggerFailure(Service::ConnectFailure reason,
                                            const std::string& detail) {
  NotifyFailure(reason, detail);
}

void VPNConnectionUnderTest::TriggerStopped() {
  NotifyStopped();
}

}  // namespace shill
