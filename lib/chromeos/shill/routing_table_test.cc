// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/routing_table.h"

#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include <deque>
#include <memory>
#include <vector>

#include <base/bind.h>
#include <base/callback.h>
//#include <base/check.h>
#include <base/containers/contains.h>
#include <base/memory/weak_ptr.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/mock_control.h"
#include "shill/net/byte_string.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/net/rtnl_message.h"

using testing::_;
using testing::Field;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;
using testing::Test;
using testing::WithArg;

namespace shill {

class RoutingTableTest : public Test {
 public:
  RoutingTableTest() : routing_table_(new RoutingTable()) {}

  void SetUp() override {
    routing_table_->rtnl_handler_ = &rtnl_handler_;
    ON_CALL(rtnl_handler_, DoSendMessage(_, _)).WillByDefault(Return(true));
  }

  void TearDown() override { RTNLHandler::GetInstance()->Stop(); }

  std::unordered_map<int, std::vector<RoutingTableEntry>>* GetRoutingTables() {
    return &routing_table_->tables_;
  }

  std::deque<RoutingTable::Query>* GetQueries() {
    return &routing_table_->route_queries_;
  }

  void SendRouteEntry(RTNLMessage::Mode mode,
                      uint32_t interface_index,
                      const RoutingTableEntry& entry);

  void SendRouteEntryWithSeqAndProto(RTNLMessage::Mode mode,
                                     uint32_t interface_index,
                                     const RoutingTableEntry& entry,
                                     uint32_t seq,
                                     unsigned char proto);

  void Start();

  int CountRoutingPolicyEntries();

  bool SetSequenceForMessage(uint32_t* seq) {
    *seq = RoutingTableTest::kTestRequestSeq;
    return true;
  }

 protected:
  static const uint32_t kTestDeviceIndex0;
  static const uint32_t kTestDeviceIndex1;
  static const char kTestDeviceName0[];
  static const char kTestDeviceNetAddress4[];
  static const char kTestForeignNetAddress4[];
  static const char kTestForeignNetGateway4[];
  static const char kTestForeignNetAddress6[];
  static const char kTestForeignNetGateway6[];
  static const char kTestGatewayAddress4[];
  static const char kTestNetAddress0[];
  static const char kTestNetAddress1[];
  static const char kTestV6NetAddress0[];
  static const char kTestV6NetAddress1[];
  static const char kTestRemoteAddress4[];
  static const char kTestRemoteNetwork4[];
  static const int kTestRemotePrefix4;
  static const uint32_t kTestRequestSeq;
  static const int kTestRouteTag;

  class QueryCallbackTarget {
   public:
    QueryCallbackTarget()
        : weak_ptr_factory_(this),
          mocked_callback_(base::Bind(&QueryCallbackTarget::MockedTarget,
                                      base::Unretained(this))),
          unreached_callback_(base::Bind(&QueryCallbackTarget::UnreachedTarget,
                                         weak_ptr_factory_.GetWeakPtr())) {}

    MOCK_METHOD(void, MockedTarget, (int, const RoutingTableEntry&));

    void UnreachedTarget(int interface_index, const RoutingTableEntry& entry) {
      CHECK(false);
    }

    const RoutingTable::QueryCallback& mocked_callback() const {
      return mocked_callback_;
    }

    const RoutingTable::QueryCallback& unreached_callback() const {
      return unreached_callback_;
    }

   private:
    base::WeakPtrFactory<QueryCallbackTarget> weak_ptr_factory_;
    const RoutingTable::QueryCallback mocked_callback_;
    const RoutingTable::QueryCallback unreached_callback_;
  };

  std::unique_ptr<RoutingTable> routing_table_;
  StrictMock<MockRTNLHandler> rtnl_handler_;
};

const uint32_t RoutingTableTest::kTestDeviceIndex0 = 12345;
const uint32_t RoutingTableTest::kTestDeviceIndex1 = 67890;
const char RoutingTableTest::kTestDeviceName0[] = "test-device0";
const char RoutingTableTest::kTestDeviceNetAddress4[] = "192.168.2.0/24";
const char RoutingTableTest::kTestForeignNetAddress4[] = "192.168.2.2";
const char RoutingTableTest::kTestForeignNetGateway4[] = "192.168.2.1";
const char RoutingTableTest::kTestForeignNetAddress6[] = "2000::/3";
const char RoutingTableTest::kTestForeignNetGateway6[] = "fe80:::::1";
const char RoutingTableTest::kTestGatewayAddress4[] = "192.168.2.254";
const char RoutingTableTest::kTestNetAddress0[] = "192.168.1.1";
const char RoutingTableTest::kTestNetAddress1[] = "192.168.1.2";
const char RoutingTableTest::kTestV6NetAddress0[] = "2001:db8::123";
const char RoutingTableTest::kTestV6NetAddress1[] = "2001:db8::456";
const char RoutingTableTest::kTestRemoteAddress4[] = "192.168.2.254";
const char RoutingTableTest::kTestRemoteNetwork4[] = "192.168.100.0";
const int RoutingTableTest::kTestRemotePrefix4 = 24;
const uint32_t RoutingTableTest::kTestRequestSeq = 456;
const int RoutingTableTest::kTestRouteTag = 789;

namespace {

MATCHER_P3(IsBlackholeRoutingPacket, family, metric, table, "") {
  const RTNLMessage::RouteStatus& status = arg->route_status();

  uint32_t priority;

  return arg->type() == RTNLMessage::kTypeRoute && arg->family() == family &&
         arg->flags() == (NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL) &&
         status.table == table && status.protocol == RTPROT_BOOT &&
         status.scope == RT_SCOPE_UNIVERSE && status.type == RTN_BLACKHOLE &&
         !arg->HasAttribute(RTA_DST) && !arg->HasAttribute(RTA_SRC) &&
         !arg->HasAttribute(RTA_GATEWAY) &&
         arg->GetAttribute(RTA_PRIORITY).ConvertToCPUUInt32(&priority) &&
         priority == metric;
}

MATCHER_P4(IsRoutingPacket, mode, index, entry, flags, "") {
  const RTNLMessage::RouteStatus& status = arg->route_status();

  uint32_t oif;
  uint32_t priority;

  return arg->type() == RTNLMessage::kTypeRoute &&
         arg->family() == entry.gateway.family() &&
         arg->flags() == (NLM_F_REQUEST | flags) &&
         entry.table == RoutingTable::GetInterfaceTableId(index) &&
         status.protocol == RTPROT_BOOT && status.scope == entry.scope &&
         status.type == RTN_UNICAST && arg->HasAttribute(RTA_DST) &&
         IPAddress(arg->family(), arg->GetAttribute(RTA_DST), status.dst_prefix)
             .Equals(entry.dst) &&
         ((!arg->HasAttribute(RTA_SRC) && entry.src.IsDefault()) ||
          (arg->HasAttribute(RTA_SRC) &&
           IPAddress(arg->family(), arg->GetAttribute(RTA_SRC),
                     status.src_prefix)
               .Equals(entry.src))) &&
         ((!arg->HasAttribute(RTA_GATEWAY) && entry.gateway.IsDefault()) ||
          (arg->HasAttribute(RTA_GATEWAY) &&
           IPAddress(arg->family(), arg->GetAttribute(RTA_GATEWAY))
               .Equals(entry.gateway))) &&
         arg->GetAttribute(RTA_OIF).ConvertToCPUUInt32(&oif) && oif == index &&
         arg->GetAttribute(RTA_PRIORITY).ConvertToCPUUInt32(&priority) &&
         priority == entry.metric;
}

}  // namespace

void RoutingTableTest::SendRouteEntry(RTNLMessage::Mode mode,
                                      uint32_t interface_index,
                                      const RoutingTableEntry& entry) {
  SendRouteEntryWithSeqAndProto(mode, interface_index, entry, 0, RTPROT_BOOT);
}

void RoutingTableTest::SendRouteEntryWithSeqAndProto(
    RTNLMessage::Mode mode,
    uint32_t interface_index,
    const RoutingTableEntry& entry,
    uint32_t seq,
    unsigned char proto) {
  RTNLMessage msg(RTNLMessage::kTypeRoute, mode, 0, seq, 0, 0,
                  entry.dst.family());

  msg.set_route_status(RTNLMessage::RouteStatus(
      entry.dst.prefix(), entry.src.prefix(),
      entry.table < 256 ? entry.table : RT_TABLE_COMPAT, proto, entry.scope,
      RTN_UNICAST, 0));

  msg.SetAttribute(RTA_DST, entry.dst.address());
  if (!entry.src.IsDefault()) {
    msg.SetAttribute(RTA_SRC, entry.src.address());
  }
  if (!entry.gateway.IsDefault()) {
    msg.SetAttribute(RTA_GATEWAY, entry.gateway.address());
  }
  msg.SetAttribute(RTA_TABLE, ByteString::CreateFromCPUUInt32(entry.table));
  msg.SetAttribute(RTA_PRIORITY, ByteString::CreateFromCPUUInt32(entry.metric));
  msg.SetAttribute(RTA_OIF, ByteString::CreateFromCPUUInt32(interface_index));

  routing_table_->RouteMsgHandler(msg);
}

void RoutingTableTest::Start() {
  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestRoute));
  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestRule));
  routing_table_->Start();
}

int RoutingTableTest::CountRoutingPolicyEntries() {
  int count = 0;
  for (const auto& table : routing_table_->policy_tables_) {
    for (auto nent = table.second.begin(); nent != table.second.end(); nent++) {
      count++;
    }
  }
  return count;
}

TEST_F(RoutingTableTest, Start) {
  Start();
}

TEST_F(RoutingTableTest, RouteAddDelete) {
  // Expect the tables to be empty by default.
  EXPECT_EQ(0, GetRoutingTables()->size());

  IPAddress default_address(IPAddress::kFamilyIPv4);
  default_address.SetAddressToDefault();

  IPAddress gateway_address0(IPAddress::kFamilyIPv4);
  gateway_address0.SetAddressFromString(kTestNetAddress0);

  int metric = 10;

  // Add a single entry.
  auto entry0 =
      RoutingTableEntry::Create(default_address, default_address,
                                gateway_address0)
          .SetMetric(metric)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0));
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry0);

  std::unordered_map<int, std::vector<RoutingTableEntry>>* tables =
      GetRoutingTables();

  // We should have a single table, which should in turn have a single entry.
  EXPECT_EQ(1, tables->size());
  EXPECT_TRUE(base::Contains(*tables, kTestDeviceIndex0));
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex0].size());

  RoutingTableEntry test_entry = (*tables)[kTestDeviceIndex0][0];
  EXPECT_EQ(entry0, test_entry);

  // Add a second entry for a different interface.
  auto entry1 =
      RoutingTableEntry::Create(default_address, default_address,
                                gateway_address0)
          .SetMetric(metric)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex1));
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex1, entry1);

  // We should have two tables, which should have a single entry each.
  EXPECT_EQ(2, tables->size());
  EXPECT_TRUE(base::Contains(*tables, kTestDeviceIndex1));
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex0].size());
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex1].size());

  test_entry = (*tables)[kTestDeviceIndex1][0];
  EXPECT_EQ(entry1, test_entry);

  IPAddress gateway_address1(IPAddress::kFamilyIPv4);
  gateway_address1.SetAddressFromString(kTestNetAddress1);

  auto entry2 =
      RoutingTableEntry::Create(default_address, default_address,
                                gateway_address1)
          .SetMetric(metric)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex1));

  // Add a second gateway route to the second interface.
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex1, entry2);

  // We should have two tables, one of which has a single entry, the other has
  // two.
  EXPECT_EQ(2, tables->size());
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex0].size());
  EXPECT_EQ(2, (*tables)[kTestDeviceIndex1].size());

  test_entry = (*tables)[kTestDeviceIndex1][1];
  EXPECT_EQ(entry2, test_entry);

  // Remove the first gateway route from the second interface.
  SendRouteEntry(RTNLMessage::kModeDelete, kTestDeviceIndex1, entry1);

  // We should be back to having one route per table.
  EXPECT_EQ(2, tables->size());
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex0].size());
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex1].size());

  test_entry = (*tables)[kTestDeviceIndex1][0];
  EXPECT_EQ(entry2, test_entry);

  // Send a duplicate of the second gateway route message, changing the metric.
  RoutingTableEntry entry3(entry2);
  entry3.metric++;
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex1, entry3);

  // Both entries should show up.
  EXPECT_EQ(2, (*tables)[kTestDeviceIndex1].size());
  test_entry = (*tables)[kTestDeviceIndex1][0];
  EXPECT_EQ(entry2, test_entry);
  test_entry = (*tables)[kTestDeviceIndex1][1];
  EXPECT_EQ(entry3, test_entry);

  // Find a matching entry.
  EXPECT_TRUE(routing_table_->GetDefaultRoute(
      kTestDeviceIndex1, IPAddress::kFamilyIPv4, &test_entry));
  EXPECT_EQ(entry2, test_entry);

  // Test that a search for a non-matching family fails.
  EXPECT_FALSE(routing_table_->GetDefaultRoute(
      kTestDeviceIndex1, IPAddress::kFamilyIPv6, &test_entry));

  // Remove last entry from an existing interface and test that we now fail.
  SendRouteEntry(RTNLMessage::kModeDelete, kTestDeviceIndex1, entry2);
  SendRouteEntry(RTNLMessage::kModeDelete, kTestDeviceIndex1, entry3);

  EXPECT_FALSE(routing_table_->GetDefaultRoute(
      kTestDeviceIndex1, IPAddress::kFamilyIPv4, &test_entry));

  // Add a route to a gateway address.
  IPAddress gateway_address(IPAddress::kFamilyIPv4);
  EXPECT_TRUE(gateway_address.SetAddressFromString(kTestNetAddress0));

  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingPacket(RTNLMessage::kModeAdd, kTestDeviceIndex1,
                                    entry1, NLM_F_CREATE | NLM_F_EXCL),
                    _));
  EXPECT_TRUE(routing_table_->SetDefaultRoute(
      kTestDeviceIndex1, gateway_address, metric,
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex1)));

  // Setting the same route on the interface with a different metric should
  // push the route with different flags to indicate we are replacing it,
  // then it should delete the old entry.
  RoutingTableEntry entry4(entry1);
  entry4.metric += 10;
  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingPacket(RTNLMessage::kModeAdd, kTestDeviceIndex1,
                                    entry4, NLM_F_CREATE | NLM_F_REPLACE),
                    _));
  EXPECT_CALL(rtnl_handler_,
              DoSendMessage(IsRoutingPacket(RTNLMessage::kModeDelete,
                                            kTestDeviceIndex1, entry1, 0),
                            _));
  EXPECT_TRUE(routing_table_->SetDefaultRoute(
      kTestDeviceIndex1, gateway_address, entry4.metric,
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex1)));

  // Test that removing the table causes the route to disappear.
  routing_table_->ResetTable(kTestDeviceIndex1);
  EXPECT_FALSE(base::Contains(*tables, kTestDeviceIndex1));
  EXPECT_FALSE(routing_table_->GetDefaultRoute(
      kTestDeviceIndex1, IPAddress::kFamilyIPv4, &test_entry));
  EXPECT_EQ(1, GetRoutingTables()->size());

  // When we set the metric on an existing route, a new add and delete
  // operation should occur.
  RoutingTableEntry entry5(entry4);
  entry5.SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0))
      .SetMetric(entry5.metric + 10);
  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingPacket(RTNLMessage::kModeAdd, kTestDeviceIndex0,
                                    entry5, NLM_F_CREATE | NLM_F_REPLACE),
                    _));
  EXPECT_CALL(rtnl_handler_,
              DoSendMessage(IsRoutingPacket(RTNLMessage::kModeDelete,
                                            kTestDeviceIndex0, entry0, 0),
                            _));
  routing_table_->SetDefaultMetric(kTestDeviceIndex0, entry5.metric);
  // Furthermore, the routing table should reflect the change in the metric
  // for the default route for the interface.
  RoutingTableEntry default_route;
  EXPECT_TRUE(routing_table_->GetDefaultRoute(
      kTestDeviceIndex0, IPAddress::kFamilyIPv4, &default_route));
  EXPECT_EQ(entry5.metric, default_route.metric);

  // Ask to flush table0.  We should see a delete message sent.
  EXPECT_CALL(rtnl_handler_,
              DoSendMessage(IsRoutingPacket(RTNLMessage::kModeDelete,
                                            kTestDeviceIndex0, entry5, 0),
                            _));
  routing_table_->FlushRoutes(kTestDeviceIndex0);
  EXPECT_EQ(0, (*tables)[kTestDeviceIndex0].size());

  // Test that the routing table size returns to zero.
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry5);
  EXPECT_EQ(1, GetRoutingTables()->size());
  routing_table_->ResetTable(kTestDeviceIndex0);
  EXPECT_EQ(0, GetRoutingTables()->size());
}

TEST_F(RoutingTableTest, PolicyRuleAddFlush) {
  Start();

  // Expect the tables to be empty by default.
  EXPECT_EQ(CountRoutingPolicyEntries(), 0);

  uint32_t table0 = routing_table_->RequestAdditionalTableId();
  uint32_t table1 = routing_table_->RequestAdditionalTableId();
  uint32_t table2 = routing_table_->RequestAdditionalTableId();
  EXPECT_GT(table0, 0);
  EXPECT_NE(table0, table1);
  EXPECT_NE(table0, table2);

  const int iface_id0 = 3;
  const int iface_id1 = 4;

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _)).WillOnce(Return(true));
  EXPECT_TRUE(routing_table_->AddRule(
      iface_id0, RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                     .SetPriority(100)
                     .SetTable(table0)
                     .SetUidRange({1000, 2000})));
  EXPECT_EQ(CountRoutingPolicyEntries(), 1);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _)).WillOnce(Return(true));
  EXPECT_TRUE(routing_table_->AddRule(
      iface_id0, RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                     .SetPriority(101)
                     .SetTable(table1)
                     .SetIif("arcbr0")));
  EXPECT_EQ(CountRoutingPolicyEntries(), 2);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _)).WillOnce(Return(true));
  EXPECT_TRUE(routing_table_->AddRule(
      iface_id1, RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                     .SetPriority(102)
                     .SetTable(table2)
                     .SetUidRange({100, 101})));
  EXPECT_EQ(CountRoutingPolicyEntries(), 3);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _))
      .Times(2)
      .WillRepeatedly(Return(true));
  routing_table_->FlushRules(iface_id0);
  EXPECT_EQ(CountRoutingPolicyEntries(), 1);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _)).WillOnce(Return(true));
  routing_table_->FlushRules(iface_id1);
  EXPECT_EQ(CountRoutingPolicyEntries(), 0);

  routing_table_->FreeAdditionalTableId(table2);
  routing_table_->FreeAdditionalTableId(table1);
  routing_table_->FreeAdditionalTableId(table0);
}

TEST_F(RoutingTableTest, LowestMetricDefault) {
  // Expect the tables to be empty by default.
  EXPECT_EQ(0, GetRoutingTables()->size());

  IPAddress default_address(IPAddress::kFamilyIPv4);
  default_address.SetAddressToDefault();

  IPAddress gateway_address0(IPAddress::kFamilyIPv4);
  gateway_address0.SetAddressFromString(kTestNetAddress0);

  auto entry =
      RoutingTableEntry::Create(default_address, default_address,
                                gateway_address0)
          .SetMetric(2)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0));

  // Add the same entry three times, with different metrics.
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry);

  entry.metric = 1;
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry);

  entry.metric = 1024;
  SendRouteEntry(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry);

  // Find a matching entry.
  RoutingTableEntry test_entry;
  EXPECT_TRUE(routing_table_->GetDefaultRoute(
      kTestDeviceIndex0, IPAddress::kFamilyIPv4, &test_entry));
  entry.metric = 1;
  EXPECT_EQ(entry, test_entry);
}

TEST_F(RoutingTableTest, IPv6StatelessAutoconfiguration) {
  // Expect the tables to be empty by default.
  EXPECT_EQ(0, GetRoutingTables()->size());

  IPAddress default_address(IPAddress::kFamilyIPv6);
  default_address.SetAddressToDefault();

  IPAddress gateway_address(IPAddress::kFamilyIPv6);
  gateway_address.SetAddressFromString(kTestV6NetAddress0);

  auto entry0 =
      RoutingTableEntry::Create(default_address, default_address,
                                gateway_address)
          .SetMetric(1024)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0));
  entry0.protocol = RTPROT_RA;

  // Simulate an RTPROT_RA kernel message indicating that it processed a
  // valid IPv6 router advertisement.
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0,
                                entry0, 0 /* seq */, RTPROT_RA);

  std::unordered_map<int, std::vector<RoutingTableEntry>>* tables =
      GetRoutingTables();

  // We should have a single table, which should in turn have a single entry.
  EXPECT_EQ(1, tables->size());
  EXPECT_TRUE(base::Contains(*tables, kTestDeviceIndex0));
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex0].size());

  RoutingTableEntry test_entry = (*tables)[kTestDeviceIndex0][0];
  EXPECT_EQ(entry0, test_entry);

  // Now send an RTPROT_RA netlink message advertising some other random
  // host.  shill should ignore these because they are frequent, and
  // not worth tracking.

  IPAddress non_default_address(IPAddress::kFamilyIPv6);
  non_default_address.SetAddressFromString(kTestV6NetAddress1);

  auto entry2 =
      RoutingTableEntry::Create(non_default_address, default_address,
                                gateway_address)
          .SetMetric(1024)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0));

  // Simulate an RTPROT_RA kernel message.
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0,
                                entry2, 0 /* seq */, RTPROT_RA);

  tables = GetRoutingTables();
  EXPECT_EQ(1, tables->size());
}

MATCHER_P2(IsRoutingQuery, destination, index, "") {
  const RTNLMessage::RouteStatus& status = arg->route_status();

  uint32_t oif;

  return arg->type() == RTNLMessage::kTypeRoute &&
         arg->family() == destination.family() &&
         arg->flags() == NLM_F_REQUEST && status.table == 0 &&
         status.protocol == 0 && status.scope == 0 && status.type == 0 &&
         arg->HasAttribute(RTA_DST) &&
         IPAddress(arg->family(), arg->GetAttribute(RTA_DST), status.dst_prefix)
             .Equals(destination) &&
         !arg->HasAttribute(RTA_SRC) && !arg->HasAttribute(RTA_GATEWAY) &&
         arg->GetAttribute(RTA_OIF).ConvertToCPUUInt32(&oif) && oif == index &&
         !arg->HasAttribute(RTA_PRIORITY);

  return false;
}

TEST_F(RoutingTableTest, RequestHostRoute) {
  IPAddress destination_address(IPAddress::kFamilyIPv4);
  destination_address.SetAddressFromString(kTestRemoteAddress4);
  destination_address.set_prefix(24);

  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingQuery(destination_address, kTestDeviceIndex0), _))
      .WillOnce(
          WithArg<1>(Invoke(this, &RoutingTableTest::SetSequenceForMessage)));
  EXPECT_TRUE(routing_table_->RequestRouteToHost(
      destination_address, kTestDeviceIndex0, kTestRouteTag,
      RoutingTable::QueryCallback(),
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));

  IPAddress gateway_address(IPAddress::kFamilyIPv4);
  gateway_address.SetAddressFromString(kTestGatewayAddress4);

  IPAddress local_address(IPAddress::kFamilyIPv4);
  local_address.SetAddressFromString(kTestDeviceNetAddress4);

  const int kMetric = 10;
  auto entry =
      RoutingTableEntry::Create(destination_address, local_address,
                                gateway_address)
          .SetMetric(kMetric)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0));

  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingPacket(RTNLMessage::kModeAdd, kTestDeviceIndex0,
                                    entry, NLM_F_CREATE | NLM_F_EXCL),
                    _));
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq, RTPROT_UNSPEC);

  std::unordered_map<int, std::vector<RoutingTableEntry>>* tables =
      GetRoutingTables();

  // We should have a single table, which should in turn have a single entry.
  EXPECT_EQ(1, tables->size());
  EXPECT_TRUE(base::Contains(*tables, kTestDeviceIndex0));
  EXPECT_EQ(1, (*tables)[kTestDeviceIndex0].size());

  // This entry's tag should match the tag we requested.
  EXPECT_EQ(kTestRouteTag, (*tables)[kTestDeviceIndex0][0].tag);

  EXPECT_TRUE(GetQueries()->empty());

  // Ask to flush routes with our tag.  We should see a delete message sent.
  EXPECT_CALL(rtnl_handler_,
              DoSendMessage(IsRoutingPacket(RTNLMessage::kModeDelete,
                                            kTestDeviceIndex0, entry, 0),
                            _));

  routing_table_->FlushRoutesWithTag(kTestRouteTag);

  // After flushing routes for this tag, we should end up with no routes.
  EXPECT_EQ(0, (*tables)[kTestDeviceIndex0].size());
}

TEST_F(RoutingTableTest, RequestHostRouteWithoutGateway) {
  IPAddress destination_address(IPAddress::kFamilyIPv4);
  destination_address.SetAddressFromString(kTestRemoteAddress4);
  destination_address.set_prefix(24);

  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingQuery(destination_address, kTestDeviceIndex0), _))
      .WillOnce(
          WithArg<1>(Invoke(this, &RoutingTableTest::SetSequenceForMessage)));
  EXPECT_TRUE(routing_table_->RequestRouteToHost(
      destination_address, kTestDeviceIndex0, kTestRouteTag,
      RoutingTable::QueryCallback(),
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));

  // Don't specify a gateway address.
  IPAddress gateway_address(IPAddress::kFamilyIPv4);

  IPAddress local_address(IPAddress::kFamilyIPv4);
  local_address.SetAddressFromString(kTestDeviceNetAddress4);

  const int kMetric = 10;
  auto entry = RoutingTableEntry::Create(destination_address, local_address,
                                         gateway_address)
                   .SetMetric(kMetric);

  // Ensure that without a gateway entry, we don't create a route.
  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _)).Times(0);
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq, RTPROT_UNSPEC);
  EXPECT_TRUE(GetQueries()->empty());
}

TEST_F(RoutingTableTest, RequestHostRouteBadSequence) {
  IPAddress destination_address(IPAddress::kFamilyIPv4);
  destination_address.SetAddressFromString(kTestRemoteAddress4);
  QueryCallbackTarget target;
  EXPECT_CALL(target, MockedTarget(_, _)).Times(0);
  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _))
      .WillOnce(
          WithArg<1>(Invoke(this, &RoutingTableTest::SetSequenceForMessage)));
  EXPECT_TRUE(routing_table_->RequestRouteToHost(
      destination_address, kTestDeviceIndex0, kTestRouteTag,
      target.mocked_callback(),
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));
  EXPECT_FALSE(GetQueries()->empty());

  auto entry = RoutingTableEntry::Create(
      destination_address, destination_address, destination_address);

  // Try a sequence arriving before the one RoutingTable is looking for.
  // This should be a no-op.
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq - 1, RTPROT_UNSPEC);
  EXPECT_FALSE(GetQueries()->empty());

  // Try a sequence arriving after the one RoutingTable is looking for.
  // This should cause the request to be purged.
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq + 1, RTPROT_UNSPEC);
  EXPECT_TRUE(GetQueries()->empty());
}

TEST_F(RoutingTableTest, RequestHostRouteWithCallback) {
  IPAddress destination_address(IPAddress::kFamilyIPv4);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _))
      .WillOnce(
          WithArg<1>(Invoke(this, &RoutingTableTest::SetSequenceForMessage)));
  QueryCallbackTarget target;
  EXPECT_TRUE(routing_table_->RequestRouteToHost(
      destination_address, -1, kTestRouteTag, target.mocked_callback(),
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));

  IPAddress gateway_address(IPAddress::kFamilyIPv4);
  gateway_address.SetAddressFromString(kTestGatewayAddress4);

  const int kMetric = 10;
  auto entry = RoutingTableEntry::Create(destination_address,
                                         IPAddress(IPAddress::kFamilyIPv4),
                                         gateway_address)
                   .SetMetric(kMetric);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _));
  EXPECT_CALL(target,
              MockedTarget(kTestDeviceIndex0,
                           Field(&RoutingTableEntry::tag, kTestRouteTag)));
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq, RTPROT_UNSPEC);
}

TEST_F(RoutingTableTest, RequestHostRouteWithoutGatewayWithCallback) {
  IPAddress destination_address(IPAddress::kFamilyIPv4);

  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _))
      .WillOnce(
          WithArg<1>(Invoke(this, &RoutingTableTest::SetSequenceForMessage)));
  QueryCallbackTarget target;
  EXPECT_TRUE(routing_table_->RequestRouteToHost(
      destination_address, -1, kTestRouteTag, target.mocked_callback(),
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));

  const int kMetric = 10;
  auto entry = RoutingTableEntry::Create(destination_address,
                                         IPAddress(IPAddress::kFamilyIPv4),
                                         IPAddress(IPAddress::kFamilyIPv4))
                   .SetMetric(kMetric);

  EXPECT_CALL(target,
              MockedTarget(kTestDeviceIndex0,
                           Field(&RoutingTableEntry::tag, kTestRouteTag)));
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq, RTPROT_UNSPEC);
}

TEST_F(RoutingTableTest, CancelQueryCallback) {
  IPAddress destination_address(IPAddress::kFamilyIPv4);
  destination_address.SetAddressFromString(kTestRemoteAddress4);
  auto target = std::make_unique<QueryCallbackTarget>();
  EXPECT_CALL(rtnl_handler_, DoSendMessage(_, _))
      .WillOnce(
          WithArg<1>(Invoke(this, &RoutingTableTest::SetSequenceForMessage)));
  EXPECT_TRUE(routing_table_->RequestRouteToHost(
      destination_address, kTestDeviceIndex0, kTestRouteTag,
      target->unreached_callback(),
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));
  ASSERT_EQ(1, GetQueries()->size());
  // Cancels the callback by destroying the owner object.
  target.reset();
  const int kMetric = 10;
  auto entry = RoutingTableEntry::Create(IPAddress(IPAddress::kFamilyIPv4),
                                         IPAddress(IPAddress::kFamilyIPv4),
                                         IPAddress(IPAddress::kFamilyIPv4))
                   .SetMetric(kMetric);
  SendRouteEntryWithSeqAndProto(RTNLMessage::kModeAdd, kTestDeviceIndex0, entry,
                                kTestRequestSeq, RTPROT_UNSPEC);
}

TEST_F(RoutingTableTest, CreateBlackholeRoute) {
  const uint32_t kMetric = 2;
  const uint32_t kTestTable = 20;
  EXPECT_CALL(rtnl_handler_,
              DoSendMessage(IsBlackholeRoutingPacket(IPAddress::kFamilyIPv6,
                                                     kMetric, kTestTable),
                            _))
      .Times(1);
  EXPECT_TRUE(routing_table_->CreateBlackholeRoute(
      kTestDeviceIndex0, IPAddress::kFamilyIPv6, kMetric, kTestTable));
}

TEST_F(RoutingTableTest, CreateLinkRoute) {
  IPAddress local_address(IPAddress::kFamilyIPv4);
  ASSERT_TRUE(local_address.SetAddressFromString(kTestNetAddress0));
  local_address.set_prefix(kTestRemotePrefix4);
  IPAddress remote_address(IPAddress::kFamilyIPv4);
  ASSERT_TRUE(remote_address.SetAddressFromString(kTestNetAddress1));
  IPAddress default_address(IPAddress::kFamilyIPv4);
  IPAddress remote_address_with_prefix(remote_address);
  remote_address_with_prefix.set_prefix(
      IPAddress::GetMaxPrefixLength(remote_address_with_prefix.family()));
  auto entry =
      RoutingTableEntry::Create(remote_address_with_prefix, local_address,
                                default_address)
          .SetScope(RT_SCOPE_LINK)
          .SetTable(RoutingTable::GetInterfaceTableId(kTestDeviceIndex0));
  EXPECT_CALL(
      rtnl_handler_,
      DoSendMessage(IsRoutingPacket(RTNLMessage::kModeAdd, kTestDeviceIndex0,
                                    entry, NLM_F_CREATE | NLM_F_EXCL),
                    _))
      .Times(1);
  EXPECT_TRUE(routing_table_->CreateLinkRoute(
      kTestDeviceIndex0, local_address, remote_address,
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));

  ASSERT_TRUE(remote_address.SetAddressFromString(kTestRemoteAddress4));
  EXPECT_FALSE(routing_table_->CreateLinkRoute(
      kTestDeviceIndex0, local_address, remote_address,
      RoutingTable::GetInterfaceTableId(kTestDeviceIndex0)));
}

}  // namespace shill
