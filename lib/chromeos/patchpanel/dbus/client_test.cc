// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dbus/client.h"

#include <base/bind.h>
#include <base/test/task_environment.h>
#include <base/threading/sequenced_task_runner_handle.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {

using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;
using ::testing::SaveArg;

class ClientTest : public testing::Test {
 protected:
  ClientTest()
      : dbus_(new dbus::MockBus{dbus::Bus::Options{}}),
        proxy_(new dbus::MockObjectProxy(
            dbus_.get(),
            kPatchPanelServiceName,
            dbus::ObjectPath(kPatchPanelServicePath))),
        client_(Client::New(dbus_, proxy_.get())) {}
  ~ClientTest() { dbus_->ShutdownAndBlock(); }

  void SetUp() override {
    EXPECT_CALL(*dbus_, GetDBusTaskRunner())
        .WillRepeatedly(Return(base::SequencedTaskRunnerHandle::Get().get()));
  }

  base::test::TaskEnvironment task_environment_;
  scoped_refptr<dbus::MockBus> dbus_;
  scoped_refptr<dbus::MockObjectProxy> proxy_;
  std::unique_ptr<Client> client_;
};

TEST_F(ClientTest, ConnectNamespace) {
  pid_t pid = 3456;
  std::string outbound_ifname = "";

  // Failure case - invalid pid
  auto result = client_->ConnectNamespace(pid, outbound_ifname, false, true,
                                          TrafficCounter::SYSTEM);
  EXPECT_FALSE(result.first.is_valid());
  EXPECT_TRUE(result.second.peer_ifname().empty());
  EXPECT_TRUE(result.second.host_ifname().empty());
  EXPECT_EQ(0, result.second.peer_ipv4_address());
  EXPECT_EQ(0, result.second.host_ipv4_address());
  EXPECT_EQ(0, result.second.ipv4_subnet().base_addr());
  EXPECT_EQ(0, result.second.ipv4_subnet().prefix_len());

  // Failure case - prohibited pid
  result = client_->ConnectNamespace(1, outbound_ifname, false, true,
                                     TrafficCounter::SYSTEM);
  EXPECT_FALSE(result.first.is_valid());

  // Success case
  patchpanel::ConnectNamespaceResponse response_proto;
  response_proto.set_peer_ifname("veth0");
  response_proto.set_host_ifname("arc_ns0");
  response_proto.set_peer_ipv4_address(Ipv4Addr(100, 115, 92, 130));
  response_proto.set_host_ipv4_address(Ipv4Addr(100, 115, 92, 129));
  auto* response_subnet = response_proto.mutable_ipv4_subnet();
  response_subnet->set_prefix_len(30);
  response_subnet->set_base_addr(Ipv4Addr(100, 115, 92, 128));
  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(response.get());
  response_writer.AppendProtoAsArrayOfBytes(response_proto);
  EXPECT_CALL(*proxy_, CallMethodAndBlock(_, _))
      .WillOnce(Return(ByMove(std::move(response))));

  result = client_->ConnectNamespace(pid, outbound_ifname, false, true,
                                     TrafficCounter::SYSTEM);
  EXPECT_TRUE(result.first.is_valid());
  EXPECT_EQ("arc_ns0", result.second.host_ifname());
  EXPECT_EQ("veth0", result.second.peer_ifname());
  EXPECT_EQ(30, result.second.ipv4_subnet().prefix_len());
  EXPECT_EQ(Ipv4Addr(100, 115, 92, 128),
            result.second.ipv4_subnet().base_addr());
  EXPECT_EQ(Ipv4Addr(100, 115, 92, 129), result.second.host_ipv4_address());
  EXPECT_EQ(Ipv4Addr(100, 115, 92, 130), result.second.peer_ipv4_address());
}

TEST_F(ClientTest, RegisterNeighborEventHandler) {
  static NeighborReachabilityEventSignal actual_signal_proto;
  static int call_num = 0;
  auto callback =
      base::BindRepeating([](const NeighborReachabilityEventSignal& sig) {
        call_num++;
        actual_signal_proto = sig;
      });

  base::RepeatingCallback<void(dbus::Signal * signal)> registered_dbus_callback;

  EXPECT_CALL(*proxy_,
              DoConnectToSignal(kPatchPanelInterface,
                                kNeighborReachabilityEventSignal, _, _))
      .WillOnce(SaveArg<2>(&registered_dbus_callback));
  client_->RegisterNeighborReachabilityEventHandler(callback);

  NeighborReachabilityEventSignal signal_proto;
  signal_proto.set_ifindex(1);
  signal_proto.set_ip_addr("1.2.3.4");
  signal_proto.set_role(NeighborReachabilityEventSignal::GATEWAY);
  signal_proto.set_type(NeighborReachabilityEventSignal::FAILED);
  dbus::Signal signal(kPatchPanelInterface, kNeighborReachabilityEventSignal);
  dbus::MessageWriter writer(&signal);
  writer.AppendProtoAsArrayOfBytes(signal_proto);

  registered_dbus_callback.Run(&signal);

  EXPECT_EQ(call_num, 1);
  EXPECT_EQ(actual_signal_proto.ifindex(), signal_proto.ifindex());
  EXPECT_EQ(actual_signal_proto.ip_addr(), signal_proto.ip_addr());
  EXPECT_EQ(actual_signal_proto.role(), signal_proto.role());
  EXPECT_EQ(actual_signal_proto.type(), signal_proto.type());
}

}  // namespace
}  // namespace patchpanel
