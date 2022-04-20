// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/connection_diagnostics.h"

#include <linux/rtnetlink.h>
#include <net/if_arp.h>

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/time/time.h>
#include <gtest/gtest.h>

#include "shill/arp_client_test_helper.h"
#include "shill/icmp_session.h"
#include "shill/manager.h"
#include "shill/mock_arp_client.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_dns_client.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_icmp_session.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_portal_detector.h"
#include "shill/mock_routing_table.h"
#include "shill/net/arp_client.h"
#include "shill/net/mock_io_handler_factory.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/routing_table_entry.h"

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::ReturnRefOfCopy;
using testing::SetArgPointee;
using testing::Test;

namespace {
constexpr const char kInterfaceName[] = "int0";
constexpr const int kInterfaceIndex = 4;
constexpr const char kDNSServer0[] = "8.8.8.8";
constexpr const char kDNSServer1[] = "8.8.4.4";
const std::vector<std::string> kIPv4DnsList{kDNSServer0, kDNSServer1};
const std::vector<std::string> kIPv6DnsList{
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
};
constexpr const char kHttpUrl[] = "http://www.gstatic.com/generate_204";
constexpr const char kHttpsUrl[] = "https://www.google.com/generate_204";
const std::vector<std::string> kFallbackHttpUrls{
    "http://www.google.com/gen_204",
    "http://play.googleapis.com/generate_204",
};
constexpr const char kDeviceMacAddressASCIIString[] = "123456";
constexpr const char kArpReplySenderMacAddressASCIIString[] = "345678";
const shill::IPAddress kIPv4DeviceAddress("100.200.43.22");
const shill::IPAddress kIPv6DeviceAddress("2001:db8::3333:4444:5555");
const shill::IPAddress kIPv4ServerAddress("8.8.8.8");
const shill::IPAddress kIPv6ServerAddress("fe80::1aa9:5ff:7ebf:14c5");
const shill::IPAddress kIPv4GatewayAddress("192.168.1.1");
const shill::IPAddress kIPv6GatewayAddress("fee2::11b2:53f:13be:125e");
const shill::IPAddress kIPv4ZeroAddress("0.0.0.0");
const std::vector<base::TimeDelta> kEmptyResult;
const std::vector<base::TimeDelta> kNonEmptyResult{base::Milliseconds(10)};
constexpr const uint8_t kMacZeroAddress[] = {0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00};
}  // namespace

namespace shill {

MATCHER_P(IsSameIPAddress, ip_addr, "") {
  return arg.Equals(ip_addr);
}

MATCHER_P(IsEventList, expected_events, "") {
  // Match on type, phase, and result, but not message.
  if (arg.size() != expected_events.size()) {
    return false;
  }
  for (size_t i = 0; i < expected_events.size(); ++i) {
    if (expected_events[i].type != arg[i].type ||
        expected_events[i].phase != arg[i].phase ||
        expected_events[i].result != arg[i].result) {
      *result_listener << "\n=== Mismatch found on expected event index " << i
                       << " ===";
      *result_listener << "\nExpected: "
                       << ConnectionDiagnostics::EventToString(
                              expected_events[i]);
      *result_listener << "\n  Actual: "
                       << ConnectionDiagnostics::EventToString(arg[i]);
      *result_listener << "\nExpected connection diagnostics events:";
      for (const auto& expected_event : expected_events) {
        *result_listener << "\n"
                         << ConnectionDiagnostics::EventToString(
                                expected_event);
      }
      *result_listener << "\nActual connection diagnostics events:";
      for (const auto& actual_event : expected_events) {
        *result_listener << "\n"
                         << ConnectionDiagnostics::EventToString(actual_event);
      }
      return false;
    }
  }
  return true;
}

MATCHER_P4(IsArpRequest, local_ip, remote_ip, local_mac, remote_mac, "") {
  if (local_ip.Equals(arg.local_ip_address()) &&
      remote_ip.Equals(arg.remote_ip_address()) &&
      local_mac.Equals(arg.local_mac_address()) &&
      remote_mac.Equals(arg.remote_mac_address())) {
    return true;
  }

  if (!local_ip.Equals(arg.local_ip_address())) {
    *result_listener << "Device IP '" << arg.local_ip_address().ToString()
                     << "' (expected '" << local_ip.ToString() << "').";
  }

  if (!remote_ip.Equals(arg.remote_ip_address())) {
    *result_listener << "Remote IP '" << arg.remote_ip_address().ToString()
                     << "' (expected '" << remote_ip.ToString() << "').";
  }

  if (!local_mac.Equals(arg.local_mac_address())) {
    *result_listener << "Device MAC '" << arg.local_mac_address().HexEncode()
                     << "' (expected " << local_mac.HexEncode() << ")'.";
  }

  if (!remote_mac.Equals(arg.remote_mac_address())) {
    *result_listener << "Remote MAC '" << arg.remote_mac_address().HexEncode()
                     << "' (expected " << remote_mac.HexEncode() << ")'.";
  }

  return false;
}

MATCHER_P(IsSameProps, props, "") {
  return (arg.portal_http_url == props.portal_http_url) &&
         (arg.portal_https_url == props.portal_https_url) &&
         (std::set<std::string>(arg.portal_fallback_http_urls.begin(),
                                arg.portal_fallback_http_urls.begin()) ==
          std::set<std::string>(props.portal_fallback_http_urls.begin(),
                                props.portal_fallback_http_urls.begin()));
}

class ConnectionDiagnosticsTest : public Test {
 public:
  ConnectionDiagnosticsTest()
      : ip_address_(kIPv4DeviceAddress),
        gateway_(kIPv4GatewayAddress),
        dns_list_(kIPv4DnsList),
        local_mac_address_(std::string(kDeviceMacAddressASCIIString), false),
        manager_(&control_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        connection_diagnostics_(kInterfaceName,
                                kInterfaceIndex,
                                kIPv4DeviceAddress,
                                kIPv4GatewayAddress,
                                kIPv4DnsList,
                                &dispatcher_,
                                &metrics_,
                                &device_info_,
                                callback_target_.result_callback()),
        portal_detector_(new NiceMock<MockPortalDetector>()) {
    connection_diagnostics_.io_handler_factory_ = &io_handler_factory_;
  }

  ~ConnectionDiagnosticsTest() override = default;

  void SetUp() override {
    ASSERT_EQ(IPAddress::kFamilyIPv4, kIPv4DeviceAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv4, kIPv4ServerAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv4, kIPv4GatewayAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv6, kIPv6ServerAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv6, kIPv6GatewayAddress.family());

    dns_client_ = new NiceMock<MockDnsClient>();
    arp_client_ = new NiceMock<MockArpClient>();
    client_test_helper_.reset(new ArpClientTestHelper(arp_client_));
    icmp_session_ = new NiceMock<MockIcmpSession>(&dispatcher_);
    connection_diagnostics_.dns_client_.reset(dns_client_);  // Passes ownership
    connection_diagnostics_.arp_client_.reset(arp_client_);  // Passes ownership
    connection_diagnostics_.icmp_session_.reset(
        icmp_session_);  // Passes ownership
    connection_diagnostics_.portal_detector_.reset(
        portal_detector_);  // Passes ownership
    connection_diagnostics_.routing_table_ = &routing_table_;
    connection_diagnostics_.rtnl_handler_ = &rtnl_handler_;
  }

  void TearDown() override {}

 protected:
  class CallbackTarget {
   public:
    CallbackTarget()
        : result_callback_(base::Bind(&CallbackTarget::ResultCallback,
                                      base::Unretained(this))) {}

    MOCK_METHOD(void,
                ResultCallback,
                (const std::string&,
                 const std::vector<ConnectionDiagnostics::Event>&));

    base::Callback<void(const std::string&,
                        const std::vector<ConnectionDiagnostics::Event>&)>&
    result_callback() {
      return result_callback_;
    }

   private:
    base::Callback<void(const std::string&,
                        const std::vector<ConnectionDiagnostics::Event>&)>
        result_callback_;
  };

  CallbackTarget& callback_target() { return callback_target_; }
  const IPAddress& gateway() { return gateway_; }

  void UseIPv6() {
    ip_address_ = kIPv6DeviceAddress;
    gateway_ = kIPv6GatewayAddress;
    dns_list_ = kIPv6DnsList;
    connection_diagnostics_.ip_address_ = kIPv6DeviceAddress;
    connection_diagnostics_.gateway_ = kIPv6GatewayAddress;
    connection_diagnostics_.dns_list_ = kIPv6DnsList;
  }

  void AddExpectedEvent(ConnectionDiagnostics::Type type,
                        ConnectionDiagnostics::Phase phase,
                        ConnectionDiagnostics::Result result) {
    expected_events_.push_back(
        ConnectionDiagnostics::Event(type, phase, result, ""));
  }

  void AddActualEvent(ConnectionDiagnostics::Type type,
                      ConnectionDiagnostics::Phase phase,
                      ConnectionDiagnostics::Result result) {
    connection_diagnostics_.diagnostic_events_.push_back(
        ConnectionDiagnostics::Event(type, phase, result, ""));
  }

  bool DoesPreviousEventMatch(ConnectionDiagnostics::Type type,
                              ConnectionDiagnostics::Phase phase,
                              ConnectionDiagnostics::Result result,
                              size_t num_events_ago) {
    return connection_diagnostics_.DoesPreviousEventMatch(type, phase, result,
                                                          num_events_ago);
  }

  // This direct call to ConnectionDiagnostics::Start does not mock the
  // return
  // value of MockPortalDetector::CreatePortalDetector, so this will crash
  // the
  // test if PortalDetector::Start is actually called. Use only for testing
  // bad input to ConnectionDiagnostics::Start.
  bool Start(const ManagerProperties& props) {
    return connection_diagnostics_.Start(props);
  }

  static ManagerProperties MakePortalProperties() {
    ManagerProperties props;
    props.portal_http_url = kHttpUrl;
    props.portal_https_url = kHttpsUrl;
    props.portal_fallback_http_urls = kFallbackHttpUrls;
    return props;
  }

  void VerifyStopped() {
    EXPECT_FALSE(connection_diagnostics_.running());
    EXPECT_EQ(0, connection_diagnostics_.num_dns_attempts_);
    EXPECT_TRUE(connection_diagnostics_.diagnostic_events_.empty());
    EXPECT_EQ(nullptr, connection_diagnostics_.dns_client_);
    EXPECT_FALSE(connection_diagnostics_.arp_client_->IsStarted());
    EXPECT_FALSE(connection_diagnostics_.icmp_session_->IsStarted());
    EXPECT_EQ(nullptr, connection_diagnostics_.portal_detector_);
    EXPECT_EQ(nullptr, connection_diagnostics_.receive_response_handler_);
    EXPECT_EQ(nullptr, connection_diagnostics_.neighbor_msg_listener_);
    EXPECT_TRUE(
        connection_diagnostics_.id_to_pending_dns_server_icmp_session_.empty());
    EXPECT_EQ(nullptr, connection_diagnostics_.target_url_);
    EXPECT_TRUE(connection_diagnostics_.route_query_callback_.IsCancelled());
    EXPECT_TRUE(
        connection_diagnostics_.route_query_timeout_callback_.IsCancelled());
    EXPECT_TRUE(
        connection_diagnostics_.arp_reply_timeout_callback_.IsCancelled());
    EXPECT_TRUE(connection_diagnostics_.neighbor_request_timeout_callback_
                    .IsCancelled());
  }

  void ExpectIcmpSessionStop() { EXPECT_CALL(*icmp_session_, Stop()); }

  void ExpectPortalDetectionStartSuccess(const ManagerProperties& props) {
    AddExpectedEvent(ConnectionDiagnostics::kTypePortalDetection,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    EXPECT_CALL(*portal_detector_,
                Start(IsSameProps(props), kInterfaceName, ip_address_,
                      dns_list_, base::TimeDelta()))
        .WillOnce(Return(true));
    EXPECT_FALSE(connection_diagnostics_.running());
    EXPECT_TRUE(connection_diagnostics_.diagnostic_events_.empty());
    EXPECT_TRUE(Start(props));
    EXPECT_TRUE(connection_diagnostics_.running());
  }

  void ExpectPortalDetectionEndContentPhaseSuccess() {
    ExpectPortalDetectionEnd(
        ConnectionDiagnostics::kPhasePortalDetectionEndContent,
        ConnectionDiagnostics::kResultSuccess, PortalDetector::Phase::kContent,
        PortalDetector::Status::kSuccess);
  }

  void ExpectPortalDetectionEndContentPhaseFailure() {
    ExpectPortalDetectionEnd(
        ConnectionDiagnostics::kPhasePortalDetectionEndContent,
        ConnectionDiagnostics::kResultFailure, PortalDetector::Phase::kContent,
        PortalDetector::Status::kFailure);
  }

  void ExpectPortalDetectionEndDNSPhaseFailure() {
    ExpectPortalDetectionEnd(ConnectionDiagnostics::kPhasePortalDetectionEndDNS,
                             ConnectionDiagnostics::kResultFailure,
                             PortalDetector::Phase::kDNS,
                             PortalDetector::Status::kFailure);
  }

  void ExpectPortalDetectionEndDNSPhaseTimeout() {
    ExpectPortalDetectionEnd(ConnectionDiagnostics::kPhasePortalDetectionEndDNS,
                             ConnectionDiagnostics::kResultTimeout,
                             PortalDetector::Phase::kDNS,
                             PortalDetector::Status::kTimeout);
  }

  void ExpectPortalDetectionEndHTTPPhaseFailure() {
    ExpectPortalDetectionEnd(
        ConnectionDiagnostics::kPhasePortalDetectionEndOther,
        ConnectionDiagnostics::kResultFailure, PortalDetector::Phase::kHTTP,
        PortalDetector::Status::kFailure);
  }

  void ExpectPingDNSServersStartSuccess() {
    ExpectPingDNSSeversStart(true, "");
  }

  void ExpectPingDNSSeversStartFailureAllAddressesInvalid() {
    ExpectPingDNSSeversStart(false,
                             ConnectionDiagnostics::kIssueDNSServersInvalid);
  }

  void ExpectPingDNSSeversStartFailureAllIcmpSessionsFailed() {
    ExpectPingDNSSeversStart(false, ConnectionDiagnostics::kIssueInternalError);
  }

  void ExpectPingDNSServersEndSuccessRetriesLeft() {
    ExpectPingDNSServersEndSuccess(true);
  }

  void ExpectPingDNSServersEndSuccessNoRetriesLeft() {
    ExpectPingDNSServersEndSuccess(false);
  }

  void ExpectPingDNSServersEndFailure() {
    AddExpectedEvent(ConnectionDiagnostics::kTypePingDNSServers,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    // Post task to find DNS server route only after all (i.e. 2) pings are
    // done.
    connection_diagnostics_.OnPingDNSServerComplete(0, kEmptyResult);
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    connection_diagnostics_.OnPingDNSServerComplete(1, kEmptyResult);
  }

  void ExpectResolveTargetServerIPAddressStartSuccess(
      IPAddress::Family family) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    ASSERT_FALSE(family == IPAddress::kFamilyUnknown);
    EXPECT_CALL(
        *dns_client_,
        Start(dns_list_, connection_diagnostics_.target_url_->host(), _))
        .WillOnce(Return(true));
    connection_diagnostics_.ResolveTargetServerIPAddress(dns_list_);
  }

  void ExpectResolveTargetServerIPAddressEndSuccess(
      const IPAddress& resolved_address) {
    ExpectResolveTargetServerIPAddressEnd(ConnectionDiagnostics::kResultSuccess,
                                          resolved_address);
  }

  void ExpectResolveTargetServerIPAddressEndTimeout() {
    ExpectResolveTargetServerIPAddressEnd(ConnectionDiagnostics::kResultTimeout,
                                          IPAddress(IPAddress::kFamilyIPv4));
  }

  void ExpectResolveTargetServerIPAddressEndFailure() {
    ExpectResolveTargetServerIPAddressEnd(ConnectionDiagnostics::kResultFailure,
                                          IPAddress(IPAddress::kFamilyIPv4));
  }

  void ExpectPingHostStartSuccess(ConnectionDiagnostics::Type ping_event_type,
                                  const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    EXPECT_CALL(*icmp_session_, Start(IsSameIPAddress(address), _, _))
        .WillOnce(Return(true));
    connection_diagnostics_.PingHost(address);
  }

  void ExpectPingHostStartFailure(ConnectionDiagnostics::Type ping_event_type,
                                  const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultFailure);
    EXPECT_CALL(*icmp_session_, Start(IsSameIPAddress(address), _, _))
        .WillOnce(Return(false));
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(
                              ConnectionDiagnostics::kIssueInternalError));
    EXPECT_CALL(callback_target(),
                ResultCallback(ConnectionDiagnostics::kIssueInternalError,
                               IsEventList(expected_events_)));
    connection_diagnostics_.PingHost(address);
  }

  void ExpectPingHostEndSuccess(ConnectionDiagnostics::Type ping_event_type,
                                const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);
    const auto& issue =
        ping_event_type == ConnectionDiagnostics::kTypePingGateway
            ? ConnectionDiagnostics::kIssueGatewayUpstream
            : ConnectionDiagnostics::kIssueHTTPBrokenPortal;
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
    EXPECT_CALL(callback_target(),
                ResultCallback(issue, IsEventList(expected_events_)));
    connection_diagnostics_.OnPingHostComplete(ping_event_type, address,
                                               kNonEmptyResult);
  }

  void ExpectPingHostEndFailure(ConnectionDiagnostics::Type ping_event_type,
                                const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    // Next action is either to find a route to the target web server, find an
    // ARP entry for the IPv4 gateway, or find a neighbor table entry for the
    // IPv6 gateway.
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    connection_diagnostics_.OnPingHostComplete(ping_event_type, address,
                                               kEmptyResult);
  }

  void ExpectFindRouteToHostStartSuccess(const IPAddress& address) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeFindRoute,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    EXPECT_CALL(routing_table_,
                RequestRouteToHost(IsSameIPAddress(address), kInterfaceIndex, _,
                                   _, kInterfaceIndex + 1000))
        .WillOnce(Return(true));
    EXPECT_CALL(
        dispatcher_,
        PostDelayedTask(_, _, ConnectionDiagnostics::kRouteQueryTimeout));
    connection_diagnostics_.FindRouteToHost(address);
    EXPECT_FALSE(
        connection_diagnostics_.route_query_timeout_callback_.IsCancelled());
  }

  void ExpectFindRouteToHostEndSuccess(const IPAddress& address_queried,
                                       bool is_local_address) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeFindRoute,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);

    IPAddress gateway(IPAddress::kFamilyIPv4);
    if (is_local_address) {
      gateway.SetAddressToDefault();
    } else {
      // Could be an IPv6 address, but we instrument this later with the
      // argument passed to ExpectPingHostStartSuccess.
      gateway = kIPv4GatewayAddress;
    }

    // Next action is either to ping the gateway, find an ARP table entry for
    // the local IPv4 web server, or find a neighbor table entry for the local
    // IPv6 web server.
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    auto entry =
        RoutingTableEntry::Create(address_queried,
                                  IPAddress(address_queried.family()), gateway)
            .SetTable(kInterfaceIndex + 1000);
    connection_diagnostics_.OnRouteQueryResponse(kInterfaceIndex, entry);
  }

  void ExpectFindRouteToHostEndFailure() {
    AddExpectedEvent(ConnectionDiagnostics::kTypeFindRoute,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(
                              ConnectionDiagnostics::kIssueRouting));
    EXPECT_CALL(callback_target(),
                ResultCallback(ConnectionDiagnostics::kIssueRouting,
                               IsEventList(expected_events_)));
    connection_diagnostics_.OnRouteQueryTimeout();
  }

  void ExpectArpTableLookupStartSuccessEndSuccess(const IPAddress& address,
                                                  bool is_gateway) {
    ExpectArpTableLookup(address, true, is_gateway);
  }

  void ExpectArpTableLookupStartSuccessEndFailure(const IPAddress& address) {
    ExpectArpTableLookup(address, false, false);
  }

  void ExpectNeighborTableLookupStartSuccess(const IPAddress& address) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeNeighborTableLookup,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestNeighbor));
    EXPECT_CALL(dispatcher_,
                PostDelayedTask(
                    _, _, ConnectionDiagnostics::kNeighborTableRequestTimeout));
    connection_diagnostics_.FindNeighborTableEntry(address);
  }

  void ExpectNeighborTableLookupEndSuccess(const IPAddress& address_queried,
                                           bool is_gateway) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeNeighborTableLookup,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);
    RTNLMessage msg(RTNLMessage::kTypeNeighbor, RTNLMessage::kModeAdd, 0, 0, 0,
                    kInterfaceIndex, IPAddress::kFamilyIPv6);
    msg.set_neighbor_status(
        RTNLMessage::NeighborStatus(NUD_REACHABLE, 0, NDA_DST));
    msg.SetAttribute(NDA_DST, address_queried.address());
    const auto& issue = is_gateway
                            ? ConnectionDiagnostics::kIssueGatewayNotResponding
                            : ConnectionDiagnostics::kIssueServerNotResponding;
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
    EXPECT_CALL(callback_target(),
                ResultCallback(issue, IsEventList(expected_events_)));
    connection_diagnostics_.OnNeighborMsgReceived(address_queried, msg);
  }

  void ExpectNeighborTableLookupEndFailureNotReachable(
      const IPAddress& address_queried, bool is_gateway) {
    ExpectNeighborTableLookupEndFailure(address_queried, is_gateway, false);
  }

  void ExpectNeighborTableLookupEndFailureNoEntry(
      const IPAddress& address_queried, bool is_gateway) {
    ExpectNeighborTableLookupEndFailure(address_queried, is_gateway, true);
  }

  void ExpectCheckIPCollisionStartSuccess() {
    AddExpectedEvent(ConnectionDiagnostics::kTypeIPCollisionCheck,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    EXPECT_CALL(device_info_, GetMacAddress(kInterfaceIndex, _))
        .WillOnce(DoAll(SetArgPointee<1>(local_mac_address_), Return(true)));
    EXPECT_CALL(*arp_client_, StartReplyListener()).WillOnce(Return(true));
    // We should send an ARP probe request for our own local IP address.
    EXPECT_CALL(*arp_client_,
                TransmitRequest(IsArpRequest(
                    kIPv4ZeroAddress, ip_address_, local_mac_address_,
                    ByteString(kMacZeroAddress, sizeof(kMacZeroAddress)))))
        .WillOnce(Return(true));
    EXPECT_CALL(dispatcher_,
                PostDelayedTask(_, _, ConnectionDiagnostics::kArpReplyTimeout));
    connection_diagnostics_.CheckIpCollision();
  }

  void ExpectCheckIPCollisionEndSuccess() {
    AddExpectedEvent(ConnectionDiagnostics::kTypeIPCollisionCheck,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);
    // Simulate ARP response from a sender with the same IP address as our
    // connection, directed at our local IP address and local MAC address.
    client_test_helper_->GeneratePacket(
        ARPOP_REPLY, ip_address_,
        ByteString(std::string(kArpReplySenderMacAddressASCIIString), false),
        ip_address_, local_mac_address_);
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(
                              ConnectionDiagnostics::kIssueIPCollision));
    EXPECT_CALL(callback_target(),
                ResultCallback(ConnectionDiagnostics::kIssueIPCollision,
                               IsEventList(expected_events_)));
    connection_diagnostics_.OnArpReplyReceived(1);
  }

  void ExpectCheckIPCollisionEndFailureGatewayArpFailed() {
    ExpectCheckIPCollisionEndFailure(
        ConnectionDiagnostics::kIssueGatewayArpFailed);
  }

  void ExpectCheckIPCollisionEndFailureServerArpFailed() {
    ExpectCheckIPCollisionEndFailure(
        ConnectionDiagnostics::kIssueServerArpFailed);
  }

 private:
  void ExpectPortalDetectionEnd(ConnectionDiagnostics::Phase diag_phase,
                                ConnectionDiagnostics::Result diag_result,
                                PortalDetector::Phase trial_phase,
                                PortalDetector::Status trial_status) {
    AddExpectedEvent(ConnectionDiagnostics::kTypePortalDetection, diag_phase,
                     diag_result);
    if (diag_phase == ConnectionDiagnostics::kPhasePortalDetectionEndContent) {
      const auto& issue = diag_result == ConnectionDiagnostics::kResultSuccess
                              ? ConnectionDiagnostics::kIssueNone
                              : ConnectionDiagnostics::kIssueCaptivePortal;
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
      EXPECT_CALL(callback_target(),
                  ResultCallback(issue, IsEventList(expected_events_)));

    } else if (diag_phase ==
                   ConnectionDiagnostics::kPhasePortalDetectionEndDNS &&
               diag_result == ConnectionDiagnostics::kResultFailure) {
      EXPECT_CALL(metrics_,
                  NotifyConnectionDiagnosticsIssue(
                      ConnectionDiagnostics::kIssueDNSServerMisconfig));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(ConnectionDiagnostics::kIssueDNSServerMisconfig,
                         IsEventList(expected_events_)));
    } else {
      // Otherwise, we end in DNS phase with a timeout, or a HTTP phase failure.
      // Either of these cases warrant further diagnostic actions.
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    }
    PortalDetector::Result result;
    result.http_phase = trial_phase;
    result.http_status = trial_status;
    result.https_phase = PortalDetector::Phase::kContent;
    result.https_status = PortalDetector::Status::kSuccess;
    connection_diagnostics_.StartAfterPortalDetectionInternal(result);
  }

  // |expected_issue| only used if |is_success| is false.
  void ExpectPingDNSSeversStart(bool is_success,
                                const std::string& expected_issue) {
    AddExpectedEvent(ConnectionDiagnostics::kTypePingDNSServers,
                     ConnectionDiagnostics::kPhaseStart,
                     is_success ? ConnectionDiagnostics::kResultSuccess
                                : ConnectionDiagnostics::kResultFailure);
    if (!is_success &&
        // If the DNS server addresses are invalid, we will not even attempt to
        // start any ICMP sessions.
        expected_issue == ConnectionDiagnostics::kIssueDNSServersInvalid) {
      connection_diagnostics_.dns_list_ = {"110.2.3", "1.5"};
    } else {
      // We are either instrumenting the success case (started pinging all
      // DNS servers successfully) or the failure case where we fail to start
      // any pings.
      ASSERT_TRUE(is_success ||
                  expected_issue == ConnectionDiagnostics::kIssueInternalError);

      auto dns_server_icmp_session_0 =
          std::make_unique<NiceMock<MockIcmpSession>>(&dispatcher_);
      auto dns_server_icmp_session_1 =
          std::make_unique<NiceMock<MockIcmpSession>>(&dispatcher_);

      EXPECT_CALL(*dns_server_icmp_session_0,
                  Start(IsSameIPAddress(IPAddress(kDNSServer0)), _, _))
          .WillOnce(Return(is_success));
      EXPECT_CALL(*dns_server_icmp_session_1,
                  Start(IsSameIPAddress(IPAddress(kDNSServer1)), _, _))
          .WillOnce(Return(is_success));

      connection_diagnostics_.id_to_pending_dns_server_icmp_session_.clear();
      connection_diagnostics_.id_to_pending_dns_server_icmp_session_[0] =
          std::move(dns_server_icmp_session_0);
      connection_diagnostics_.id_to_pending_dns_server_icmp_session_[1] =
          std::move(dns_server_icmp_session_1);
    }

    if (is_success) {
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(_)).Times(0);
      EXPECT_CALL(callback_target(), ResultCallback(_, _)).Times(0);
    } else {
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(expected_issue));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(expected_issue, IsEventList(expected_events_)));
    }
    connection_diagnostics_.PingDNSServers();
    if (is_success) {
      EXPECT_EQ(2, connection_diagnostics_
                       .id_to_pending_dns_server_icmp_session_.size());
    } else {
      EXPECT_TRUE(connection_diagnostics_.id_to_pending_dns_server_icmp_session_
                      .empty());
    }
  }

  void ExpectResolveTargetServerIPAddressEnd(
      ConnectionDiagnostics::Result result, const IPAddress& resolved_address) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                     ConnectionDiagnostics::kPhaseEnd, result);
    Error error;
    if (result == ConnectionDiagnostics::kResultSuccess) {
      error.Populate(Error::kSuccess);
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    } else if (result == ConnectionDiagnostics::kResultTimeout) {
      error.Populate(Error::kOperationTimeout);
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    } else {
      error.Populate(Error::kOperationFailed);
      EXPECT_CALL(metrics_,
                  NotifyConnectionDiagnosticsIssue(
                      ConnectionDiagnostics::kIssueDNSServerMisconfig));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(ConnectionDiagnostics::kIssueDNSServerMisconfig,
                         IsEventList(expected_events_)));
    }
    connection_diagnostics_.OnDNSResolutionComplete(error, resolved_address);
  }

  void ExpectPingDNSServersEndSuccess(bool retries_left) {
    AddExpectedEvent(ConnectionDiagnostics::kTypePingDNSServers,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);
    if (retries_left) {
      EXPECT_LT(connection_diagnostics_.num_dns_attempts_,
                ConnectionDiagnostics::kMaxDNSRetries);
    } else {
      EXPECT_GE(connection_diagnostics_.num_dns_attempts_,
                ConnectionDiagnostics::kMaxDNSRetries);
    }
    // Post retry task or report done only after all (i.e. 2) pings are done.
    connection_diagnostics_.OnPingDNSServerComplete(0, kNonEmptyResult);
    if (retries_left) {
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(_)).Times(0);
      EXPECT_CALL(callback_target(), ResultCallback(_, _)).Times(0);
    } else {
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
          .Times(0);
      EXPECT_CALL(metrics_,
                  NotifyConnectionDiagnosticsIssue(
                      ConnectionDiagnostics::kIssueDNSServerNoResponse));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(ConnectionDiagnostics::kIssueDNSServerNoResponse,
                         IsEventList(expected_events_)));
    }
    connection_diagnostics_.OnPingDNSServerComplete(1, kNonEmptyResult);
  }

  void ExpectArpTableLookup(const IPAddress& address,
                            bool success,
                            bool is_gateway) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeArpTableLookup,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    AddExpectedEvent(ConnectionDiagnostics::kTypeArpTableLookup,
                     ConnectionDiagnostics::kPhaseEnd,
                     success ? ConnectionDiagnostics::kResultSuccess
                             : ConnectionDiagnostics::kResultFailure);
    EXPECT_CALL(device_info_, GetMacAddressOfPeer(kInterfaceIndex,
                                                  IsSameIPAddress(address), _))
        .WillOnce(Return(success));
    if (success) {
      const auto& issue =
          is_gateway ? ConnectionDiagnostics::kIssueGatewayNotResponding
                     : ConnectionDiagnostics::kIssueServerNotResponding;
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
      EXPECT_CALL(callback_target(),
                  ResultCallback(issue, IsEventList(expected_events_)));
    } else {
      // Checking for IP collision.
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    }
    connection_diagnostics_.FindArpTableEntry(address);
  }

  void ExpectCheckIPCollisionEndFailure(const std::string& expected_issue) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeIPCollisionCheck,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(expected_issue));
    EXPECT_CALL(callback_target(),
                ResultCallback(expected_issue, IsEventList(expected_events_)));
    connection_diagnostics_.OnArpRequestTimeout();
  }

  void ExpectNeighborTableLookupEndFailure(const IPAddress& address_queried,
                                           bool is_gateway,
                                           bool is_timeout) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeNeighborTableLookup,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    std::string issue;
    if (is_timeout) {
      issue = is_gateway ? ConnectionDiagnostics::kIssueGatewayNoNeighborEntry
                         : ConnectionDiagnostics::kIssueServerNoNeighborEntry;
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
      EXPECT_CALL(callback_target(),
                  ResultCallback(issue, IsEventList(expected_events_)));
      connection_diagnostics_.OnNeighborTableRequestTimeout(address_queried);
    } else {
      issue =
          is_gateway
              ? ConnectionDiagnostics::kIssueGatewayNeighborEntryNotConnected
              : ConnectionDiagnostics::kIssueServerNeighborEntryNotConnected;
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
      EXPECT_CALL(callback_target(),
                  ResultCallback(issue, IsEventList(expected_events_)));
      RTNLMessage msg(RTNLMessage::kTypeNeighbor, RTNLMessage::kModeAdd, 0, 0,
                      0, kInterfaceIndex, IPAddress::kFamilyIPv6);
      msg.set_neighbor_status(
          RTNLMessage::NeighborStatus(NUD_FAILED, 0, NDA_DST));
      msg.SetAttribute(NDA_DST, address_queried.address());
      connection_diagnostics_.OnNeighborMsgReceived(address_queried, msg);
    }
  }

  IPAddress ip_address_;
  IPAddress gateway_;
  std::vector<std::string> dns_list_;
  ByteString local_mac_address_;
  CallbackTarget callback_target_;
  MockControl control_;
  NiceMock<MockMetrics> metrics_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  MockIOHandlerFactory io_handler_factory_;
  ConnectionDiagnostics connection_diagnostics_;
  NiceMock<MockEventDispatcher> dispatcher_;
  NiceMock<MockRoutingTable> routing_table_;
  NiceMock<MockRTNLHandler> rtnl_handler_;
  std::unique_ptr<ArpClientTestHelper> client_test_helper_;

  // Used only for EXPECT_CALL(). Objects are owned by
  // |connection_diagnostics_|.
  NiceMock<MockDnsClient>* dns_client_;
  NiceMock<MockArpClient>* arp_client_;
  NiceMock<MockIcmpSession>* icmp_session_;
  NiceMock<MockPortalDetector>* portal_detector_;

  // For each test, all events we expect to appear in the final result are
  // accumulated in this vector.
  std::vector<ConnectionDiagnostics::Event> expected_events_;
};

TEST_F(ConnectionDiagnosticsTest, DoesPreviousEventMatch) {
  // If |diagnostic_events| is empty, we should always fail to match an event.
  EXPECT_FALSE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypePortalDetection,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 0));
  EXPECT_FALSE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypePortalDetection,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 2));

  AddActualEvent(ConnectionDiagnostics::kTypePortalDetection,
                 ConnectionDiagnostics::kPhaseStart,
                 ConnectionDiagnostics::kResultSuccess);
  AddActualEvent(ConnectionDiagnostics::kTypePortalDetection,
                 ConnectionDiagnostics::kPhasePortalDetectionEndOther,
                 ConnectionDiagnostics::kResultFailure);
  AddActualEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                 ConnectionDiagnostics::kPhaseStart,
                 ConnectionDiagnostics::kResultSuccess);
  AddActualEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                 ConnectionDiagnostics::kPhaseEnd,
                 ConnectionDiagnostics::kResultSuccess);

  // Matching out of bounds should fail. (4 events total, so 4 events before the
  // last event is out of bounds).
  EXPECT_FALSE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypePortalDetection,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 4));

  // Valid matches.
  EXPECT_TRUE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypePortalDetection,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 3));
  EXPECT_TRUE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 1));
  EXPECT_TRUE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                             ConnectionDiagnostics::kPhaseEnd,
                             ConnectionDiagnostics::kResultSuccess, 0));
}

TEST_F(ConnectionDiagnosticsTest, StartWhileRunning) {
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);  // Start diagnostics;
  EXPECT_FALSE(Start(props));
}

TEST_F(ConnectionDiagnosticsTest, StartWithBadURL) {
  const std::string kBadURL("http://www.foo.com:x");  // Colon but no port
  // IcmpSession::Stop will be called once when the bad URL is rejected.
  ExpectIcmpSessionStop();
  const auto props = MakePortalProperties();
  EXPECT_FALSE(Start(props));
  // IcmpSession::Stop will be called a second time when
  // |connection_diagnostics_| is destructed.
  ExpectIcmpSessionStop();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_InternalError) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, and we
  // attempt to ping the target web server but fail because of an internal
  // error.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartFailure(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PortalDetectionContentPhase_Success) {
  // Portal detection ends successfully in content phase, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndContentPhaseSuccess();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PortalDetectionContentPhase_Failure) {
  // Portal detection ends unsuccessfully in content phase, so we end
  // diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndContentPhaseFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_DNSFailure_1) {
  // Portal detection ends with a DNS failure (not timeout), so we end
  // diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_DNSFailure_2) {
  // Portal detection ends in HTTP phase, DNS resolution fails (not timeout), so
  // we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerStartFailure_1) {
  // Portal detection ends with a DNS timeout, and we attempt to pinging DNS
  // servers, but fail to start any IcmpSessions, so end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSSeversStartFailureAllIcmpSessionsFailed();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerStartFailure_2) {
  // Portal detection ends with a DNS timeout, and we attempt to pinging DNS
  // servers, but all DNS servers configured for this connection have invalid IP
  // addresses, so we fail to start ping DNs servers, and end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSSeversStartFailureAllAddressesInvalid();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerEndSuccess_NoRetries_1) {
  // Portal detection ends with a DNS timeout, pinging DNS servers succeeds, DNS
  // resolution times out, pinging DNS servers succeeds again, and DNS
  // resolution times out again. End diagnostics because we have no more DNS
  // retries left.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessNoRetriesLeft();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerEndSuccess_NoRetries_2) {
  // Portal detection ends in HTTP phase, DNS resolution times out, pinging DNS
  // servers succeeds, DNS resolution times out again, pinging DNS servers
  // succeeds. End diagnostics because we have no more DNS retries left.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessNoRetriesLeft();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingTargetIPSuccess_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, and pinging
  // the resolved IP address succeeds, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingTargetIPSuccess_2) {
  // Portal detection ends with a DNS timeout, pinging DNS servers succeeds, DNS
  // resolution succeeds, and pinging the resolved IP address succeeds, so we
  // end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingTargetIPSuccess_3) {
  // Portal detection ends in HTTP phase, DNS resolution times out, pinging DNS
  // servers succeeds, DNS resolution succeeds, and pinging the resolved IP
  // address succeeds, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_FindRouteFailure_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we fail to get a route for the IP address,
  // so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_FindRoute_Failure_2) {
  // Portal detection ends with a DNS timeout, pinging DNS servers succeeds, DNS
  // resolution succeeds, pinging the resolved IP address fails, and we fail to
  // get a route for the IP address, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_FindRouteFailure_3) {
  // Portal detection ends in HTTP phase, DNS resolution times out, pinging DNS
  // servers succeeds, DNS resolution succeeds, pinging the resolved IP address
  // fails, and we fail to get a route for the IP address, so we end
  // diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_FindRouteFailure_4) {
  // Portal detection ends with a DNS timeout, pinging DNS servers fails, get a
  // route for the first DNS server, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndFailure();
  ExpectFindRouteToHostStartSuccess(gateway());
  ExpectFindRouteToHostEndFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_1_IPv4) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is remote, so ping the local gateway and succeed, so
  // we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_1_IPv6) {
  // Same as above, but this time the resolved IP address of the target URL
  // is IPv6.
  UseIPv6();

  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv6);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv6ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv6ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv6ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv6ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_2) {
  // Portal detection ends with a DNS timeout, pinging DNS servers succeeds, DNS
  // resolution succeeds, pinging the resolved IP address fails, and we
  // successfully get route for the IP address. This address is remote, so ping
  // the local gateway and succeed, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndDNSPhaseTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_3) {
  // Portal detection ends in HTTP phase, DNS resolution times out, pinging DNS
  // servers succeeds, DNS resolution succeeds, pinging the resolved IP address
  // fails, and we successfully get route for the IP address. This address is
  // remote, so ping the local gateway. The ping succeeds, so we end
  // diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

// Note: for the test below, several other possible paths through the diagnostic
// state machine that will lead us to end diagnostics at ARP table lookup or IP
// collision check are not explicitly tested. We do this to avoid redundancy
// since the above tests have already exercised these sub-paths extensively,

TEST_F(ConnectionDiagnosticsTest, EndWith_FindArpTableEntrySuccess_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is remote, pinging the local gateway fails, and we
  // find an ARP table entry for the gateway address, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingGateway, gateway());
  ExpectArpTableLookupStartSuccessEndSuccess(gateway(), true);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_FindArpTableEntrySuccess_2) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is local, and we find an ARP table entry for this
  // address, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, true);
  ExpectArpTableLookupStartSuccessEndSuccess(kIPv4ServerAddress, false);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_IPCollisionSuccess_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is remote, pinging the local gateway fails, ARP table
  // lookup fails, we check for IP collision and find one, so we end
  // diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingGateway, gateway());
  ExpectArpTableLookupStartSuccessEndFailure(gateway());
  ExpectCheckIPCollisionStartSuccess();
  ExpectCheckIPCollisionEndSuccess();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_IPCollisionSuccess_2) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is local, ARP table lookup fails, we check for IP
  // collision and find one, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, true);
  ExpectArpTableLookupStartSuccessEndSuccess(kIPv4ServerAddress, false);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_IPCollisionFailure_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is remote, pinging the local gateway fails, ARP table
  // lookup fails, we check for IP collision and do not find one, so we end
  // diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingGateway, gateway());
  ExpectArpTableLookupStartSuccessEndFailure(gateway());
  ExpectCheckIPCollisionStartSuccess();
  ExpectCheckIPCollisionEndFailureGatewayArpFailed();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_IPCollisionFailure_2) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is local, ARP table lookup fails, we check for IP
  // collision and do not find one, so we end diagnostics.
  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv4ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv4ServerAddress, true);
  ExpectArpTableLookupStartSuccessEndFailure(kIPv4ServerAddress);
  ExpectCheckIPCollisionStartSuccess();
  ExpectCheckIPCollisionEndFailureServerArpFailed();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_kTypeNeighborTableLookupSuccess_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is remote, pinging the local IPv6 gateway fails,
  // and we find a neighbor table entry for the gateway. End diagnostics.
  UseIPv6();

  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv6);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv6ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv6ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv6ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv6ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingGateway, gateway());
  ExpectNeighborTableLookupStartSuccess(gateway());
  ExpectNeighborTableLookupEndSuccess(gateway(), true);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_kTypeNeighborTableLookupSuccess_2) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, we succeed in getting a route for the IP
  // address. This address is a local IPv6 address, and we find a neighbor table
  // entry for it. End diagnostics.
  UseIPv6();

  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv6);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv6ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv6ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv6ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv6ServerAddress, true);
  ExpectNeighborTableLookupStartSuccess(kIPv6ServerAddress);
  ExpectNeighborTableLookupEndSuccess(kIPv6ServerAddress, false);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_kTypeNeighborTableLookupFailure_1) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, and we successfully get route for the IP
  // address. This address is remote, pinging the local IPv6 gateway fails, and
  // we find a neighbor table entry for the gateway, but it is not marked as
  // reachable. End diagnostics.
  UseIPv6();

  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv6);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv6ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv6ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv6ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv6ServerAddress, false);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingGateway, gateway());
  ExpectNeighborTableLookupStartSuccess(gateway());
  ExpectNeighborTableLookupEndFailureNotReachable(gateway(), true);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_kTypeNeighborTableLookupFailure_2) {
  // Portal detection ends in HTTP phase, DNS resolution succeeds, pinging the
  // resolved IP address fails, we succeed in getting a route for the IP
  // address. This address is a local IPv6 address, and we do not find a
  // neighbor table entry for it. End diagnostics.
  UseIPv6();

  const auto props = MakePortalProperties();
  ExpectPortalDetectionStartSuccess(props);
  ExpectPortalDetectionEndHTTPPhaseFailure();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv6);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv6ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv6ServerAddress);
  ExpectFindRouteToHostStartSuccess(kIPv6ServerAddress);
  ExpectFindRouteToHostEndSuccess(kIPv6ServerAddress, true);
  ExpectNeighborTableLookupStartSuccess(kIPv6ServerAddress);
  ExpectNeighborTableLookupEndFailureNoEntry(kIPv6ServerAddress, false);
  VerifyStopped();
}

}  // namespace shill
