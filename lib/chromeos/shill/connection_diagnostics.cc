// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/connection_diagnostics.h"

#include <linux/rtnetlink.h>

#include <base/bind.h>
//#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "shill/device_info.h"
#include "shill/dns_client.h"
#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/http_url.h"
#include "shill/icmp_session.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/arp_client.h"
#include "shill/net/arp_packet.h"
#include "shill/net/byte_string.h"
#include "shill/net/io_handler_factory.h"
#include "shill/net/ip_address.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_listener.h"
#include "shill/net/rtnl_message.h"
#include "shill/routing_table.h"
#include "shill/routing_table_entry.h"

namespace {
// These strings are dependent on ConnectionDiagnostics::Type. Any changes to
// this array should be synced with ConnectionDiagnostics::Type.
const char* const kEventNames[] = {
    "Portal detection",         "Ping DNS servers",      "DNS resolution",
    "Ping (target web server)", "Ping (gateway)",        "Find route",
    "ARP table lookup",         "Neighbor table lookup", "IP collision check"};
// These strings are dependent on ConnectionDiagnostics::Phase. Any changes to
// this array should be synced with ConnectionDiagnostics::Phase.
const char* const kPhaseNames[] = {"Start", "End", "End (Content)", "End (DNS)",
                                   "End (HTTP/CXN)"};
// These strings are dependent on ConnectionDiagnostics::Result. Any changes to
// this array should be synced with ConnectionDiagnostics::Result.
const char* const kResultNames[] = {"Success", "Failure", "Timeout"};
// After we fail to ping the gateway, we 1) start ARP lookup, 2) fail ARP
// lookup, 3) start IP collision check, 4) end IP collision check.
const int kNumEventsFromPingGatewayEndToIpCollisionCheckEnd = 4;
const char kIPv4ZeroAddress[] = "0.0.0.0";
const uint8_t kMacZeroAddress[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

}  // namespace

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
static std::string ObjectID(const ConnectionDiagnostics* n) {
  return "(connection_diagnostics)";
}
}  // namespace Logging

const char ConnectionDiagnostics::kIssueIPCollision[] =
    "IP collision detected. Another host on the local network has been "
    "assigned the same IP address.";
const char ConnectionDiagnostics::kIssueRouting[] = "Routing problem detected.";
const char ConnectionDiagnostics::kIssueHTTPBrokenPortal[] =
    "Target URL is pingable. Connectivity problems might be caused by HTTP "
    "issues on the server or a broken portal.";
const char ConnectionDiagnostics::kIssueDNSServerMisconfig[] =
    "DNS servers responding to DNS queries, but sending invalid responses. "
    "DNS servers might be misconfigured.";
const char ConnectionDiagnostics::kIssueDNSServerNoResponse[] =
    "At least one DNS server is pingable, but is not responding to DNS "
    "requests. DNS server issue detected.";
const char ConnectionDiagnostics::kIssueNoDNSServersConfigured[] =
    "No DNS servers have been configured for this connection -- either the "
    "DHCP server or user configuration is invalid.";
const char ConnectionDiagnostics::kIssueDNSServersInvalid[] =
    "All configured DNS server addresses are invalid.";
const char ConnectionDiagnostics::kIssueNone[] =
    "No connection issue detected.";
const char ConnectionDiagnostics::kIssueCaptivePortal[] =
    "Trapped in captive portal.";
const char ConnectionDiagnostics::kIssueGatewayUpstream[] =
    "We can find a route to the target web server at a remote IP address, "
    "and the local gateway is pingable. Gatway issue or upstream "
    "connectivity problem detected.";
const char ConnectionDiagnostics::kIssueGatewayNotResponding[] =
    "This gateway appears to be on the local network, but is not responding to "
    "pings.";
const char ConnectionDiagnostics::kIssueServerNotResponding[] =
    "This web server appears to be on the local network, but is not responding "
    "to pings.";
const char ConnectionDiagnostics::kIssueGatewayArpFailed[] =
    "No ARP entry for the gateway. Either the gateway does not exist on the "
    "local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueServerArpFailed[] =
    "No ARP entry for the web server. Either the web server does not exist on "
    "the local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueInternalError[] =
    "The connection diagnostics encountered an internal failure.";
const char ConnectionDiagnostics::kIssueGatewayNoNeighborEntry[] =
    "No neighbor table entry for the gateway. Either the gateway does not "
    "exist on the local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueServerNoNeighborEntry[] =
    "No neighbor table entry for the web server. Either the web server does "
    "not exist on the local network, or there are link layer issues.";
const char ConnectionDiagnostics::kIssueGatewayNeighborEntryNotConnected[] =
    "Neighbor table entry for the gateway is not in a connected state. Either "
    "the web server does not exist on the local network, or there are link "
    "layer issues.";
const char ConnectionDiagnostics::kIssueServerNeighborEntryNotConnected[] =
    "Neighbor table entry for the web server is not in a connected state. "
    "Either the web server does not exist on the local network, or there are "
    "link layer issues.";
const int ConnectionDiagnostics::kMaxDNSRetries = 2;

ConnectionDiagnostics::ConnectionDiagnostics(
    std::string iface_name,
    int iface_index,
    const IPAddress& ip_address,
    const IPAddress& gateway,
    const std::vector<std::string>& dns_list,
    EventDispatcher* dispatcher,
    Metrics* metrics,
    const DeviceInfo* device_info,
    const ResultCallback& result_callback)
    : dispatcher_(dispatcher),
      metrics_(metrics),
      routing_table_(RoutingTable::GetInstance()),
      rtnl_handler_(RTNLHandler::GetInstance()),
      device_info_(device_info),
      iface_name_(iface_name),
      iface_index_(iface_index),
      ip_address_(ip_address),
      gateway_(gateway),
      dns_list_(dns_list),
      arp_client_(new ArpClient(iface_index_)),
      icmp_session_(new IcmpSession(dispatcher_)),
      num_dns_attempts_(0),
      running_(false),
      result_callback_(result_callback),
      io_handler_factory_(IOHandlerFactory::GetInstance()),
      weak_ptr_factory_(this) {
  dns_client_.reset(
      new DnsClient(ip_address.family(), iface_name,
                    DnsClient::kDnsTimeoutMilliseconds, dispatcher_,
                    Bind(&ConnectionDiagnostics::OnDNSResolutionComplete,
                         weak_ptr_factory_.GetWeakPtr())));
  portal_detector_.reset(new PortalDetector(
      dispatcher_, metrics_,
      base::Bind(&ConnectionDiagnostics::StartAfterPortalDetectionInternal,
                 weak_ptr_factory_.GetWeakPtr())));
  for (size_t i = 0; i < dns_list_.size(); i++) {
    id_to_pending_dns_server_icmp_session_[i] =
        std::make_unique<IcmpSession>(dispatcher_);
  }
}

ConnectionDiagnostics::~ConnectionDiagnostics() {
  Stop();
}

bool ConnectionDiagnostics::Start(const ManagerProperties& props) {
  SLOG(this, 3) << __func__ << "(" << props.portal_http_url << ")";

  if (running()) {
    LOG(ERROR) << "Connection diagnostics already started";
    return false;
  }

  target_url_.reset(new HttpUrl());
  if (!target_url_->ParseFromString(props.portal_http_url)) {
    LOG(ERROR) << "Failed to parse URL string: " << props.portal_http_url;
    Stop();
    return false;
  }

  if (!portal_detector_->Start(props, iface_name_, ip_address_, dns_list_)) {
    Stop();
    return false;
  }

  running_ = true;
  AddEvent(kTypePortalDetection, kPhaseStart, kResultSuccess);
  return true;
}

bool ConnectionDiagnostics::StartAfterPortalDetection(
    const std::string& url_string, const PortalDetector::Result& result) {
  SLOG(this, 3) << __func__ << "(" << url_string << ")";

  if (running()) {
    LOG(ERROR) << "Connection diagnostics already started";
    return false;
  }

  target_url_.reset(new HttpUrl());
  if (!target_url_->ParseFromString(url_string)) {
    LOG(ERROR) << "Failed to parse URL string: " << url_string;
    Stop();
    return false;
  }

  running_ = true;
  dispatcher_->PostTask(
      FROM_HERE,
      base::BindOnce(&ConnectionDiagnostics::StartAfterPortalDetectionInternal,
                     weak_ptr_factory_.GetWeakPtr(), result));
  return true;
}

void ConnectionDiagnostics::Stop() {
  SLOG(this, 3) << __func__;

  running_ = false;
  num_dns_attempts_ = 0;
  diagnostic_events_.clear();
  dns_client_.reset();
  arp_client_->Stop();
  icmp_session_->Stop();
  portal_detector_.reset();
  receive_response_handler_.reset();
  neighbor_msg_listener_.reset();
  id_to_pending_dns_server_icmp_session_.clear();
  target_url_.reset();
  route_query_callback_.Cancel();
  route_query_timeout_callback_.Cancel();
  arp_reply_timeout_callback_.Cancel();
  neighbor_request_timeout_callback_.Cancel();
}

// static
std::string ConnectionDiagnostics::EventToString(const Event& event) {
  auto message = base::StringPrintf(
      "Event: %-26sPhase: %-17sResult: %-10s", kEventNames[event.type],
      kPhaseNames[event.phase], kResultNames[event.result]);
  if (!event.message.empty()) {
    message.append("Msg: " + event.message);
  }
  return message;
}

void ConnectionDiagnostics::AddEvent(Type type, Phase phase, Result result) {
  AddEventWithMessage(type, phase, result, "");
}

void ConnectionDiagnostics::AddEventWithMessage(Type type,
                                                Phase phase,
                                                Result result,
                                                const std::string& message) {
  diagnostic_events_.push_back(Event(type, phase, result, message));
}

void ConnectionDiagnostics::ReportResultAndStop(const std::string& issue) {
  SLOG(this, 3) << __func__;

  metrics_->NotifyConnectionDiagnosticsIssue(issue);
  if (!result_callback_.is_null()) {
    LOG(INFO) << "Connection diagnostics events:";
    for (size_t i = 0; i < diagnostic_events_.size(); ++i) {
      LOG(INFO) << "  #" << i << ": " << EventToString(diagnostic_events_[i]);
    }
    LOG(INFO) << "Connection diagnostics completed. Connection issue: "
              << issue;
    result_callback_.Run(issue, diagnostic_events_);
  }
  Stop();
}

void ConnectionDiagnostics::StartAfterPortalDetectionInternal(
    const PortalDetector::Result& result) {
  SLOG(this, 3) << __func__;

  Result result_type;
  if (result.http_status == PortalDetector::Status::kSuccess) {
    result_type = kResultSuccess;
  } else if (result.http_status == PortalDetector::Status::kTimeout) {
    result_type = kResultTimeout;
  } else {
    result_type = kResultFailure;
  }

  switch (result.http_phase) {
    case PortalDetector::Phase::kContent: {
      AddEvent(kTypePortalDetection, kPhasePortalDetectionEndContent,
               result_type);
      // We have found the issue if we end in the content phase.
      ReportResultAndStop(result_type == kResultSuccess ? kIssueNone
                                                        : kIssueCaptivePortal);
      break;
    }
    case PortalDetector::Phase::kDNS: {
      AddEvent(kTypePortalDetection, kPhasePortalDetectionEndDNS, result_type);
      if (result.http_status == PortalDetector::Status::kSuccess) {
        LOG(ERROR) << __func__
                   << ": portal detection should not end with "
                      "success status in DNS phase";
        ReportResultAndStop(kIssueInternalError);
      } else if (result.http_status == PortalDetector::Status::kTimeout) {
        // DNS timeout occurred in portal detection. Ping DNS servers to make
        // sure they are reachable.
        dispatcher_->PostTask(
            FROM_HERE, base::BindOnce(&ConnectionDiagnostics::PingDNSServers,
                                      weak_ptr_factory_.GetWeakPtr()));
      } else {
        ReportResultAndStop(kIssueDNSServerMisconfig);
      }
      break;
    }
    case PortalDetector::Phase::kConnection:
    case PortalDetector::Phase::kHTTP:
    case PortalDetector::Phase::kUnknown:
    default: {
      AddEvent(kTypePortalDetection, kPhasePortalDetectionEndOther,
               result_type);
      if (result.http_status == PortalDetector::Status::kSuccess) {
        LOG(ERROR) << __func__
                   << ": portal detection should not end with success status in"
                      " Connection/HTTP/Unknown phase";
        ReportResultAndStop(kIssueInternalError);
      } else {
        dispatcher_->PostTask(
            FROM_HERE,
            base::BindOnce(&ConnectionDiagnostics::ResolveTargetServerIPAddress,
                           weak_ptr_factory_.GetWeakPtr(), dns_list_));
      }
      break;
    }
  }
}

void ConnectionDiagnostics::ResolveTargetServerIPAddress(
    const std::vector<std::string>& dns_list) {
  SLOG(this, 3) << __func__;

  Error e;
  if (!dns_client_->Start(dns_list, target_url_->host(), &e)) {
    LOG(ERROR) << __func__ << ": could not start DNS -- " << e.message();
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseStart, kResultFailure,
                        e.message());
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseStart, kResultSuccess,
                      base::StringPrintf("Attempt #%d", num_dns_attempts_));
  SLOG(this, 3) << __func__ << ": looking up " << target_url_->host()
                << " (attempt " << num_dns_attempts_ << ")";
  ++num_dns_attempts_;
}

void ConnectionDiagnostics::PingDNSServers() {
  SLOG(this, 3) << __func__;

  if (dns_list_.empty()) {
    LOG(ERROR) << __func__ << ": no DNS servers for this connection";
    AddEventWithMessage(kTypePingDNSServers, kPhaseStart, kResultFailure,
                        "No DNS servers for this connection");
    ReportResultAndStop(kIssueNoDNSServersConfigured);
    return;
  }

  pingable_dns_servers_.clear();
  size_t num_invalid_dns_server_addr = 0;
  size_t num_failed_icmp_session_start = 0;
  for (size_t i = 0; i < dns_list_.size(); ++i) {
    // If we encounter any errors starting ping for any DNS server, carry on
    // attempting to ping the other DNS servers rather than failing. We only
    // need to successfully ping a single DNS server to decide whether or not
    // DNS servers can be reached.
    IPAddress dns_server_ip_addr(dns_list_[i]);
    if (dns_server_ip_addr.family() == IPAddress::kFamilyUnknown) {
      LOG(ERROR) << __func__
                 << ": could not parse DNS server IP address from string";
      ++num_invalid_dns_server_addr;
      id_to_pending_dns_server_icmp_session_.erase(i);
      continue;
    }

    auto session_iter = id_to_pending_dns_server_icmp_session_.find(i);
    if (session_iter == id_to_pending_dns_server_icmp_session_.end())
      continue;

    if (!session_iter->second->Start(
            dns_server_ip_addr, iface_index_,
            base::Bind(&ConnectionDiagnostics::OnPingDNSServerComplete,
                       weak_ptr_factory_.GetWeakPtr(), i))) {
      LOG(ERROR) << "Failed to initiate ping for DNS server at "
                 << dns_server_ip_addr.ToString();
      ++num_failed_icmp_session_start;
      id_to_pending_dns_server_icmp_session_.erase(i);
      continue;
    }

    SLOG(this, 3) << __func__ << ": pinging DNS server at "
                  << dns_server_ip_addr.ToString();
  }

  if (id_to_pending_dns_server_icmp_session_.empty()) {
    AddEventWithMessage(
        kTypePingDNSServers, kPhaseStart, kResultFailure,
        "Could not start ping for any of the given DNS servers");
    if (num_invalid_dns_server_addr == dns_list_.size()) {
      ReportResultAndStop(kIssueDNSServersInvalid);
    } else if (num_failed_icmp_session_start == dns_list_.size()) {
      ReportResultAndStop(kIssueInternalError);
    }
  } else {
    AddEvent(kTypePingDNSServers, kPhaseStart, kResultSuccess);
  }
}

void ConnectionDiagnostics::FindRouteToHost(const IPAddress& address) {
  SLOG(this, 3) << __func__;

  RoutingTableEntry entry;
  route_query_callback_.Reset(
      base::Bind(&ConnectionDiagnostics::OnRouteQueryResponse,
                 weak_ptr_factory_.GetWeakPtr()));
  int table_id = RoutingTable::GetInterfaceTableId(iface_index_);
  if (!routing_table_->RequestRouteToHost(address, iface_index_, -1,
                                          route_query_callback_.callback(),
                                          table_id)) {
    route_query_callback_.Cancel();
    LOG(ERROR) << __func__ << ": could not request route to "
               << address.ToString();
    AddEventWithMessage(kTypeFindRoute, kPhaseStart, kResultFailure,
                        "Could not request route to " + address.ToString());
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  // RoutingTable implementation does not have a built-in timeout mechanism
  // for un-replied route requests, so use our own.
  route_query_timeout_callback_.Reset(
      base::Bind(&ConnectionDiagnostics::OnRouteQueryTimeout,
                 weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(
      FROM_HERE, route_query_timeout_callback_.callback(), kRouteQueryTimeout);
  AddEventWithMessage(kTypeFindRoute, kPhaseStart, kResultSuccess,
                      "Requesting route to " + address.ToString());
}

void ConnectionDiagnostics::FindArpTableEntry(const IPAddress& address) {
  SLOG(this, 3) << __func__;

  if (address.family() != IPAddress::kFamilyIPv4) {
    // We only perform ARP table lookups for IPv4 addresses.
    LOG(ERROR) << __func__ << ": " << address.ToString()
               << " is not an IPv4 address";
    AddEventWithMessage(kTypeArpTableLookup, kPhaseStart, kResultFailure,
                        address.ToString() + " is not an IPv4 address");
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  AddEventWithMessage(kTypeArpTableLookup, kPhaseStart, kResultSuccess,
                      "Finding ARP table entry for " + address.ToString());
  ByteString target_mac_address;
  if (device_info_->GetMacAddressOfPeer(iface_index_, address,
                                        &target_mac_address)) {
    AddEventWithMessage(kTypeArpTableLookup, kPhaseEnd, kResultSuccess,
                        "Found ARP table entry for " + address.ToString());
    ReportResultAndStop(address.Equals(gateway_) ? kIssueGatewayNotResponding
                                                 : kIssueServerNotResponding);
    return;
  }

  AddEventWithMessage(
      kTypeArpTableLookup, kPhaseEnd, kResultFailure,
      "Could not find ARP table entry for " + address.ToString());
  dispatcher_->PostTask(FROM_HERE,
                        base::BindOnce(&ConnectionDiagnostics::CheckIpCollision,
                                       weak_ptr_factory_.GetWeakPtr()));
}

void ConnectionDiagnostics::FindNeighborTableEntry(const IPAddress& address) {
  SLOG(this, 3) << __func__;

  if (address.family() != IPAddress::kFamilyIPv6) {
    // We only perform neighbor table lookups for IPv6 addresses.
    LOG(ERROR) << __func__ << ": " << address.ToString()
               << " is not an IPv6 address";
    AddEventWithMessage(kTypeNeighborTableLookup, kPhaseStart, kResultFailure,
                        address.ToString() + " is not an IPv6 address");
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  neighbor_msg_listener_.reset(new RTNLListener(
      RTNLHandler::kRequestNeighbor,
      base::BindRepeating(&ConnectionDiagnostics::OnNeighborMsgReceived,
                          weak_ptr_factory_.GetWeakPtr(), address)));
  rtnl_handler_->RequestDump(RTNLHandler::kRequestNeighbor);

  neighbor_request_timeout_callback_.Reset(
      base::Bind(&ConnectionDiagnostics::OnNeighborTableRequestTimeout,
                 weak_ptr_factory_.GetWeakPtr(), address));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               neighbor_request_timeout_callback_.callback(),
                               kNeighborTableRequestTimeout);
  AddEventWithMessage(kTypeNeighborTableLookup, kPhaseStart, kResultSuccess,
                      "Finding neighbor table entry for " + address.ToString());
}

void ConnectionDiagnostics::CheckIpCollision() {
  SLOG(this, 3) << __func__;

  if (!device_info_->GetMacAddress(iface_index_, &mac_address_)) {
    LOG(ERROR) << __func__ << ": could not get local MAC address";
    AddEventWithMessage(kTypeIPCollisionCheck, kPhaseStart, kResultFailure,
                        "Could not get local MAC address");
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  if (!arp_client_->StartReplyListener()) {
    LOG(ERROR) << __func__ << ": failed to start ARP client";
    AddEventWithMessage(kTypeIPCollisionCheck, kPhaseStart, kResultFailure,
                        "Failed to start ARP client");
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  receive_response_handler_.reset(io_handler_factory_->CreateIOReadyHandler(
      arp_client_->socket(), IOHandler::kModeInput,
      base::Bind(&ConnectionDiagnostics::OnArpReplyReceived,
                 weak_ptr_factory_.GetWeakPtr())));

  // Create an 'Arp Probe' Packet.
  ArpPacket request(IPAddress(std::string(kIPv4ZeroAddress)), ip_address_,
                    mac_address_,
                    ByteString(kMacZeroAddress, sizeof(kMacZeroAddress)));
  if (!arp_client_->TransmitRequest(request)) {
    LOG(ERROR) << __func__ << ": failed to send ARP request";
    AddEventWithMessage(kTypeIPCollisionCheck, kPhaseStart, kResultFailure,
                        "Failed to send ARP request");
    arp_client_->Stop();
    receive_response_handler_.reset();
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  arp_reply_timeout_callback_.Reset(
      base::Bind(&ConnectionDiagnostics::OnArpRequestTimeout,
                 weak_ptr_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(
      FROM_HERE, arp_reply_timeout_callback_.callback(), kArpReplyTimeout);
  AddEvent(kTypeIPCollisionCheck, kPhaseStart, kResultSuccess);
}

void ConnectionDiagnostics::PingHost(const IPAddress& address) {
  SLOG(this, 3) << __func__;

  Type event_type =
      address.Equals(gateway_) ? kTypePingGateway : kTypePingTargetServer;
  if (!icmp_session_->Start(
          address, iface_index_,
          base::Bind(&ConnectionDiagnostics::OnPingHostComplete,
                     weak_ptr_factory_.GetWeakPtr(), event_type, address))) {
    LOG(ERROR) << __func__ << ": failed to start ICMP session with "
               << address.ToString();
    AddEventWithMessage(
        event_type, kPhaseStart, kResultFailure,
        "Failed to start ICMP session with " + address.ToString());
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  AddEventWithMessage(event_type, kPhaseStart, kResultSuccess,
                      "Pinging " + address.ToString());
}

void ConnectionDiagnostics::OnPingDNSServerComplete(
    int dns_server_index, const std::vector<base::TimeDelta>& result) {
  SLOG(this, 3) << __func__ << "(DNS server index " << dns_server_index << ")";

  if (!id_to_pending_dns_server_icmp_session_.erase(dns_server_index)) {
    // This should not happen, since we expect exactly one callback for each
    // IcmpSession started with a unique |dns_server_index| value in
    // ConnectionDiagnostics::PingDNSServers. However, if this does happen for
    // any reason, |id_to_pending_dns_server_icmp_session_| might never become
    // empty, and we might never move to the next step after pinging DNS
    // servers. Stop diagnostics immediately to prevent this from happening.
    LOG(ERROR) << __func__
               << ": no matching pending DNS server ICMP session found";
    ReportResultAndStop(kIssueInternalError);
    return;
  }

  if (IcmpSession::AnyRepliesReceived(result)) {
    pingable_dns_servers_.push_back(dns_list_[dns_server_index]);
  }
  if (!id_to_pending_dns_server_icmp_session_.empty()) {
    SLOG(this, 3) << __func__ << ": not yet finished pinging all DNS servers";
    return;
  }

  if (pingable_dns_servers_.empty()) {
    // Use the first DNS server on the list and diagnose its connectivity.
    IPAddress first_dns_server_ip_addr(dns_list_[0]);
    if (first_dns_server_ip_addr.family() == IPAddress::kFamilyUnknown) {
      LOG(ERROR) << __func__ << ": could not parse DNS server IP address "
                 << dns_list_[0];
      AddEventWithMessage(kTypePingDNSServers, kPhaseEnd, kResultFailure,
                          "Could not parse DNS "
                          "server IP address " +
                              dns_list_[0]);
      ReportResultAndStop(kIssueInternalError);
      return;
    }
    AddEventWithMessage(
        kTypePingDNSServers, kPhaseEnd, kResultFailure,
        "No DNS servers responded to pings. Pinging first DNS server at " +
            first_dns_server_ip_addr.ToString());
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&ConnectionDiagnostics::FindRouteToHost,
                                  weak_ptr_factory_.GetWeakPtr(),
                                  first_dns_server_ip_addr));
    return;
  }

  if (pingable_dns_servers_.size() != dns_list_.size()) {
    AddEventWithMessage(kTypePingDNSServers, kPhaseEnd, kResultSuccess,
                        "Pinged some, but not all, DNS servers successfully");
  } else {
    AddEventWithMessage(kTypePingDNSServers, kPhaseEnd, kResultSuccess,
                        "Pinged all DNS servers successfully");
  }

  if (num_dns_attempts_ < kMaxDNSRetries) {
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::ResolveTargetServerIPAddress,
                       weak_ptr_factory_.GetWeakPtr(), pingable_dns_servers_));
  } else {
    SLOG(this, 3) << __func__ << ": max DNS resolution attempts reached";
    ReportResultAndStop(kIssueDNSServerNoResponse);
  }
}

void ConnectionDiagnostics::OnDNSResolutionComplete(const Error& error,
                                                    const IPAddress& address) {
  SLOG(this, 3) << __func__;

  if (error.IsSuccess()) {
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseEnd, kResultSuccess,
                        "Target address is " + address.ToString());
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&ConnectionDiagnostics::PingHost,
                                  weak_ptr_factory_.GetWeakPtr(), address));
  } else if (error.type() == Error::kOperationTimeout) {
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseEnd, kResultTimeout,
                        "DNS resolution timed out: " + error.message());
    dispatcher_->PostTask(FROM_HERE,
                          base::BindOnce(&ConnectionDiagnostics::PingDNSServers,
                                         weak_ptr_factory_.GetWeakPtr()));
  } else {
    AddEventWithMessage(kTypeResolveTargetServerIP, kPhaseEnd, kResultFailure,
                        "DNS resolution failed: " + error.message());
    ReportResultAndStop(kIssueDNSServerMisconfig);
  }
}

void ConnectionDiagnostics::OnPingHostComplete(
    Type ping_event_type,
    const IPAddress& address_pinged,
    const std::vector<base::TimeDelta>& result) {
  SLOG(this, 3) << __func__;

  auto message = base::StringPrintf("Destination: %s,  Latencies: ",
                                    address_pinged.ToString().c_str());
  for (const auto& latency : result) {
    if (latency.is_zero()) {
      message.append("NA ");
    } else {
      message.append(base::StringPrintf("%4.2fms ", latency.InMillisecondsF()));
    }
  }

  Result result_type =
      IcmpSession::AnyRepliesReceived(result) ? kResultSuccess : kResultFailure;
  if (IcmpSession::IsPacketLossPercentageGreaterThan(result, 50)) {
    LOG(WARNING) << __func__ << ": high packet loss when pinging "
                 << address_pinged.ToString();
  }
  AddEventWithMessage(ping_event_type, kPhaseEnd, result_type, message);
  if (result_type == kResultSuccess) {
    // If pinging the target web server succeeded, we have found a HTTP issue or
    // broken portal. Otherwise, if pinging the gateway succeeded, we have found
    // an upstream connectivity problem or gateway issue.
    ReportResultAndStop(ping_event_type == kTypePingGateway
                            ? kIssueGatewayUpstream
                            : kIssueHTTPBrokenPortal);
  } else if (result_type == kResultFailure &&
             ping_event_type == kTypePingTargetServer) {
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::FindRouteToHost,
                       weak_ptr_factory_.GetWeakPtr(), address_pinged));
  } else if (result_type == kResultFailure &&
             ping_event_type == kTypePingGateway &&
             address_pinged.family() == IPAddress::kFamilyIPv4) {
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::FindArpTableEntry,
                       weak_ptr_factory_.GetWeakPtr(), address_pinged));
  } else {
    // We failed to ping an IPv6 gateway. Check for neighbor table entry for
    // this gateway.
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::FindNeighborTableEntry,
                       weak_ptr_factory_.GetWeakPtr(), address_pinged));
  }
}

void ConnectionDiagnostics::OnArpReplyReceived(int fd) {
  SLOG(this, 3) << __func__ << "(fd " << fd << ")";

  ArpPacket packet;
  ByteString sender;
  if (!arp_client_->ReceivePacket(&packet, &sender)) {
    return;
  }
  // According to RFC 5227, we only check the sender's ip address.
  if (ip_address_.Equals(packet.local_ip_address())) {
    arp_reply_timeout_callback_.Cancel();
    AddEventWithMessage(kTypeIPCollisionCheck, kPhaseEnd, kResultSuccess,
                        "IP collision found");
    ReportResultAndStop(kIssueIPCollision);
  }
}

void ConnectionDiagnostics::OnArpRequestTimeout() {
  SLOG(this, 3) << __func__;

  AddEventWithMessage(kTypeIPCollisionCheck, kPhaseEnd, kResultFailure,
                      "No IP collision found");
  // TODO(samueltan): perform link-level diagnostics.
  if (DoesPreviousEventMatch(
          kTypePingGateway, kPhaseEnd, kResultFailure,
          kNumEventsFromPingGatewayEndToIpCollisionCheckEnd)) {
    // We came here from failing to ping the gateway.
    ReportResultAndStop(kIssueGatewayArpFailed);
  } else {
    // Otherwise, we must have come here from failing to ping the target web
    // server and successfully finding a route.
    ReportResultAndStop(kIssueServerArpFailed);
  }
}

void ConnectionDiagnostics::OnNeighborMsgReceived(
    const IPAddress& address_queried, const RTNLMessage& msg) {
  SLOG(this, 3) << __func__;

  DCHECK(msg.type() == RTNLMessage::kTypeNeighbor);
  const RTNLMessage::NeighborStatus& neighbor = msg.neighbor_status();

  if (neighbor.type != NDA_DST || !msg.HasAttribute(NDA_DST)) {
    SLOG(this, 4) << __func__ << ": neighbor message has no destination";
    return;
  }

  IPAddress address(msg.family(), msg.GetAttribute(NDA_DST));
  if (!address.Equals(address_queried)) {
    SLOG(this, 4) << __func__ << ": destination address (" << address.ToString()
                  << ") does not match address queried ("
                  << address_queried.ToString() << ")";
    return;
  }

  neighbor_request_timeout_callback_.Cancel();
  if (!(neighbor.state & (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE))) {
    AddEventWithMessage(
        kTypeNeighborTableLookup, kPhaseEnd, kResultFailure,
        base::StringPrintf(
            "Neighbor table entry for %s is not in a connected state "
            "(actual state = 0x%2x)",
            address_queried.ToString().c_str(), neighbor.state));
    ReportResultAndStop(address_queried.Equals(gateway_)
                            ? kIssueGatewayNeighborEntryNotConnected
                            : kIssueServerNeighborEntryNotConnected);
    return;
  }

  AddEventWithMessage(
      kTypeNeighborTableLookup, kPhaseEnd, kResultSuccess,
      "Neighbor table entry found for " + address_queried.ToString());
  ReportResultAndStop(address_queried.Equals(gateway_)
                          ? kIssueGatewayNotResponding
                          : kIssueServerNotResponding);
}

void ConnectionDiagnostics::OnNeighborTableRequestTimeout(
    const IPAddress& address_queried) {
  SLOG(this, 3) << __func__;

  AddEventWithMessage(
      kTypeNeighborTableLookup, kPhaseEnd, kResultFailure,
      "Failed to find neighbor table entry for " + address_queried.ToString());
  ReportResultAndStop(address_queried.Equals(gateway_)
                          ? kIssueGatewayNoNeighborEntry
                          : kIssueServerNoNeighborEntry);
}

void ConnectionDiagnostics::OnRouteQueryResponse(
    int interface_index, const RoutingTableEntry& entry) {
  SLOG(this, 3) << __func__ << "(interface " << interface_index << ")";

  if (interface_index != iface_index_) {
    SLOG(this, 3) << __func__
                  << ": route query response not meant for this interface";
    return;
  }

  route_query_timeout_callback_.Cancel();
  AddEventWithMessage(
      kTypeFindRoute, kPhaseEnd, kResultSuccess,
      base::StringPrintf("Found route to %s (%s)", entry.dst.ToString().c_str(),
                         entry.gateway.IsDefault() ? "remote" : "local"));
  if (!entry.gateway.IsDefault()) {
    // We have a route to a remote destination, so ping the route gateway to
    // check if we have a means of reaching this host.
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::PingHost,
                       weak_ptr_factory_.GetWeakPtr(), entry.gateway));
  } else if (entry.dst.family() == IPAddress::kFamilyIPv4) {
    // We have a route to a local IPv4 destination, so check for an ARP table
    // entry.
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&ConnectionDiagnostics::FindArpTableEntry,
                                  weak_ptr_factory_.GetWeakPtr(), entry.dst));
  } else {
    // We have a route to a local IPv6 destination, so check for a neighbor
    // table entry.
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&ConnectionDiagnostics::FindNeighborTableEntry,
                       weak_ptr_factory_.GetWeakPtr(), entry.dst));
  }
}

void ConnectionDiagnostics::OnRouteQueryTimeout() {
  SLOG(this, 3) << __func__;

  AddEvent(kTypeFindRoute, kPhaseEnd, kResultFailure);
  ReportResultAndStop(kIssueRouting);
}

bool ConnectionDiagnostics::DoesPreviousEventMatch(Type type,
                                                   Phase phase,
                                                   Result result,
                                                   size_t num_events_ago) {
  int event_index = diagnostic_events_.size() - 1 - num_events_ago;
  if (event_index < 0) {
    LOG(ERROR) << __func__ << ": requested event " << num_events_ago
               << " before the last event, but we only have "
               << diagnostic_events_.size() << " logged";
    return false;
  }

  return (diagnostic_events_[event_index].type == type &&
          diagnostic_events_[event_index].phase == phase &&
          diagnostic_events_[event_index].result == result);
}

}  // namespace shill
