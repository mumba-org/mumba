// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/network_monitor_service.h"

#include <memory>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <utility>

#include <base/bind.h>
#include <base/notreached.h>
#include <base/strings/strcat.h>
#include <base/threading/sequenced_task_runner_handle.h>
#include <base/logging.h>
#include <shill/net/rtnl_handler.h>
#include <shill/net/rtnl_listener.h>

namespace patchpanel {

namespace {
// The set of states which indicate the neighbor is valid. Copied from
// /include/net/neighbour.h in linux kernel.
constexpr uint16_t kNUDStateValid = NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE |
                                    NUD_PROBE | NUD_STALE | NUD_DELAY;

std::string NUDStateToString(uint16_t state) {
  switch (state) {
    case NUD_INCOMPLETE:
      return "NUD_INCOMPLETE";
    case NUD_REACHABLE:
      return "NUD_REACHABLE";
    case NUD_STALE:
      return "NUD_STALE";
    case NUD_DELAY:
      return "NUD_DELAY";
    case NUD_PROBE:
      return "NUD_PROBE";
    case NUD_FAILED:
      return "NUD_FAILED";
    case NUD_NOARP:
      return "NUD_NOARP";
    case NUD_PERMANENT:
      return "NUD_PERMANENT";
    case NUD_NONE:
      return "NUD_NONE";
    default:
      return "Unknown NUD state " + std::to_string(state);
  }
}

bool IsIPv6LinkLocalAddress(const shill::IPAddress& addr) {
  if (addr.family() != shill::IPAddress::kFamilyIPv6)
    return false;
  return shill::IPAddress("fe80::", 64).CanReachAddress(addr);
}

// We cannot set the state of an address to NUD_PROBE when the kernel doesn't
// know its MAC address, and thus the state should be in NUD_VALID. We don't
// probe for the other states in NUD_VALID because:
// - NUD_DELAY will soon become NUD_PROBE or NUD_REACHABLE;
// - NUD_PROBE means the kernel is already probing;
// - NUD_PERMANENT and NUD_NOARP are special states and it will not be
// changed.
bool NeedProbeForState(uint16_t current_state) {
  return current_state & (NUD_STALE | NUD_REACHABLE);
}

}  // namespace

NeighborLinkMonitor::NeighborLinkMonitor(
    int ifindex,
    const std::string& ifname,
    shill::RTNLHandler* rtnl_handler,
    NeighborReachabilityEventHandler* neighbor_event_handler)
    : ifindex_(ifindex),
      ifname_(ifname),
      rtnl_handler_(rtnl_handler),
      neighbor_event_handler_(neighbor_event_handler) {}

NeighborLinkMonitor::WatchingEntry::WatchingEntry(shill::IPAddress addr,
                                                  NeighborRole role)
    : addr(std::move(addr)), role(role) {}

std::string NeighborLinkMonitor::NeighborRoleToString(
    NeighborLinkMonitor::NeighborRole role) {
  switch (role) {
    case NeighborLinkMonitor::NeighborRole::kGateway:
      return "gateway";
    case NeighborLinkMonitor::NeighborRole::kDNSServer:
      return "dns_server";
    case NeighborLinkMonitor::NeighborRole::kGatewayAndDNSServer:
      return "gateway and dns_server";
    default:
      NOTREACHED();
  }
}

std::string NeighborLinkMonitor::WatchingEntry::ToString() const {
  return base::StrCat({"{ addr: ", addr.ToString(),
                       ", role: ", NeighborRoleToString(role),
                       ", state: ", NUDStateToString(nud_state), " }"});
}

void NeighborLinkMonitor::AddWatchingEntries(
    int prefix_length,
    const std::string& addr,
    const std::string& gateway,
    const std::vector<std::string>& dns_addrs) {
  shill::IPAddress gateway_addr(gateway);
  if (!gateway_addr.IsValid()) {
    LOG(ERROR) << "Gateway address " << gateway << " is not valid";
    return;
  }
  UpdateWatchingEntry(gateway_addr, NeighborRole::kGateway);

  shill::IPAddress local_addr(addr, prefix_length);
  if (!local_addr.IsValid()) {
    LOG(ERROR) << "Local address " << local_addr << " is not valid";
    return;
  }

  int watching_dns_num = 0;
  int skipped_dns_num = 0;
  for (const auto& dns : dns_addrs) {
    shill::IPAddress dns_addr(dns);
    if (!dns_addr.IsValid()) {
      LOG(ERROR) << "DNS server address is not valid";
      return;
    }
    if (!local_addr.CanReachAddress(dns_addr) &&
        !IsIPv6LinkLocalAddress(dns_addr)) {
      skipped_dns_num++;
      continue;
    }
    watching_dns_num++;
    UpdateWatchingEntry(dns_addr, NeighborRole::kDNSServer);
  }
  LOG(INFO) << shill::IPAddress::GetAddressFamilyName(local_addr.family())
            << " watching entries added on " << ifname_
            << ": skipped_dns_num=" << skipped_dns_num
            << " ,watching_dns_num=" << watching_dns_num;
}

void NeighborLinkMonitor::UpdateWatchingEntry(const shill::IPAddress& addr,
                                              NeighborRole role) {
  const auto it = watching_entries_.find(addr);
  if (it == watching_entries_.end()) {
    watching_entries_.emplace(std::piecewise_construct, std::make_tuple(addr),
                              std::make_tuple(addr, role));
    return;
  }

  constexpr uint8_t gateway_flag = static_cast<uint8_t>(NeighborRole::kGateway);
  constexpr uint8_t dns_server_flag =
      static_cast<uint8_t>(NeighborRole::kDNSServer);
  uint8_t current_flags =
      static_cast<uint8_t>(it->second.role) | static_cast<uint8_t>(role);
  switch (current_flags) {
    case gateway_flag:
      it->second.role = NeighborRole::kGateway;
      break;
    case dns_server_flag:
      it->second.role = NeighborRole::kDNSServer;
      break;
    case gateway_flag | dns_server_flag:
      it->second.role = NeighborRole::kGatewayAndDNSServer;
      break;
    default:
      NOTREACHED();
  }
}

void NeighborLinkMonitor::OnIPConfigChanged(
    const ShillClient::IPConfig& ipconfig) {
  LOG(INFO) << "ipconfigs changed on " << ifname_
            << ", update watching entries";
  const auto old_watching_entries = std::move(watching_entries_);
  watching_entries_.clear();

  if (!ipconfig.ipv4_address.empty())
    AddWatchingEntries(ipconfig.ipv4_prefix_length, ipconfig.ipv4_address,
                       ipconfig.ipv4_gateway, ipconfig.ipv4_dns_addresses);
  if (!ipconfig.ipv6_address.empty())
    AddWatchingEntries(ipconfig.ipv6_prefix_length, ipconfig.ipv6_address,
                       ipconfig.ipv6_gateway, ipconfig.ipv6_dns_addresses);

  if (watching_entries_.empty()) {
    LOG(INFO) << "Stop due to empty watching list on " << ifname_;
    Stop();
    return;
  }

  Start();

  // If one address is in our list before, restores its NUD state and does
  // nothing; otherwise, we need to do a dump.
  bool has_new_entry = false;
  for (auto new_it = watching_entries_.begin();
       new_it != watching_entries_.end(); new_it++) {
    const auto old_it = old_watching_entries.find(new_it->first);
    if (old_it == old_watching_entries.end())
      has_new_entry = true;
    else
      new_it->second.nud_state = old_it->second.nud_state;
  }

  if (has_new_entry)
    SendNeighborDumpRTNLMessage();
}

void NeighborLinkMonitor::Start() {
  if (listener_ != nullptr)
    return;

  listener_ = std::make_unique<shill::RTNLListener>(
      shill::RTNLHandler::kRequestNeighbor,
      base::BindRepeating(&NeighborLinkMonitor::OnNeighborMessage,
                          base::Unretained(this)),
      rtnl_handler_);
  probe_timer_.Start(FROM_HERE, kActiveProbeInterval, this,
                     &NeighborLinkMonitor::ProbeAll);
}

void NeighborLinkMonitor::Stop() {
  listener_ = nullptr;
  probe_timer_.Stop();
}

void NeighborLinkMonitor::ProbeAll() {
  bool has_unknown_entry = false;
  for (const auto& addr_entry : watching_entries_) {
    const auto& entry = addr_entry.second;
    if (entry.nud_state == NUD_NONE) {
      has_unknown_entry = true;
      // This could happen for temporary failures, but continuously reaching
      // here for one entry means that, we have an entry in ipconfig which is
      // not accessible.
      LOG(INFO) << "Has an unknown entry on " << ifname_ << " with "
                << entry.ToString();
    } else if (NeedProbeForState(entry.nud_state)) {
      SendNeighborProbeRTNLMessage(entry);
    }
  }

  if (has_unknown_entry)
    SendNeighborDumpRTNLMessage();
}

void NeighborLinkMonitor::SendNeighborDumpRTNLMessage() {
  // |seq| will be set by RTNLHandler.
  // TODO(jiejiang): Specify the family instead of kFamilyUnknown. This
  // optimization could reduce the amount of data received for each request.
  auto msg = std::make_unique<shill::RTNLMessage>(
      shill::RTNLMessage::kTypeNeighbor, shill::RTNLMessage::kModeGet,
      NLM_F_REQUEST | NLM_F_DUMP, 0 /* seq */, 0 /* pid */, ifindex_,
      shill::IPAddress::kFamilyUnknown);

  // TODO(jiejiang): We may get an error of errno=16 (Device or resource busy)
  // from kernel here. We may need to serialize the DUMP requests.
  if (!rtnl_handler_->SendMessage(std::move(msg), nullptr /* msg_seq */))
    LOG(WARNING) << "Failed to send neighbor dump message for on " << ifname_;
}

void NeighborLinkMonitor::SendNeighborProbeRTNLMessage(
    const WatchingEntry& entry) {
  // |seq| will be set by RTNLHandler.
  auto msg = std::make_unique<shill::RTNLMessage>(
      shill::RTNLMessage::kTypeNeighbor, shill::RTNLMessage::kModeAdd,
      NLM_F_REQUEST | NLM_F_REPLACE, 0 /* seq */, 0 /* pid */, ifindex_,
      entry.addr.family());

  // We don't need to set |ndm_flags| and |ndm_type| for this message.
  msg->set_neighbor_status(shill::RTNLMessage::NeighborStatus(
      NUD_PROBE, 0 /* ndm_flags */, 0 /* ndm_type */));
  msg->SetAttribute(NDA_DST, entry.addr.address());

  if (!rtnl_handler_->SendMessage(std::move(msg), nullptr /* msg_seq */))
    LOG(WARNING) << "Failed to send neighbor probe message for "
                 << entry.ToString() << " on " << ifname_;
}

void NeighborLinkMonitor::OnNeighborMessage(const shill::RTNLMessage& msg) {
  if (msg.interface_index() != ifindex_)
    return;

  auto family = msg.family();
  shill::ByteString dst = msg.GetAttribute(NDA_DST);
  shill::IPAddress addr(family, dst);
  if (!addr.IsValid()) {
    LOG(WARNING) << "Got neighbor message with invalid addr " << addr;
    return;
  }

  auto it = watching_entries_.find(addr);
  if (it == watching_entries_.end())
    return;

  uint16_t old_nud_state = it->second.nud_state;
  uint16_t new_nud_state;
  if (msg.mode() == shill::RTNLMessage::kModeDelete)
    new_nud_state = NUD_NONE;
  else
    new_nud_state = msg.neighbor_status().state;

  it->second.nud_state = new_nud_state;

  // Probes this entry if we know it for the first time (state changed
  // from NUD_NONE, e.g., the monitor just started, or this entry has been
  // removed once).
  if (old_nud_state == NUD_NONE && NeedProbeForState(new_nud_state))
    SendNeighborProbeRTNLMessage(it->second);

  // When the "valid" state (i.e., whether kernel knows the MAC address of a
  // neighbor) changed from valid to invalid, it doesn't always mean a failure
  // happens: e.g., an NUD_STALE entry could be removed if it's not been
  // accessed for a while. But it's still an uncommon case here, because we're
  // trying to make kernel probing the neighbor periodically. Thus we would
  // expect the NUD state stays valid if the neighbor is reachable.
  bool old_nud_state_is_valid = old_nud_state & kNUDStateValid;
  bool new_nud_state_is_valid = new_nud_state & kNUDStateValid;
  if (old_nud_state_is_valid != new_nud_state_is_valid) {
    LOG(INFO) << "NUD state changed on " << ifname_ << " for "
              << it->second.ToString()
              << ", old_state=" << NUDStateToString(old_nud_state);
  }

  if (new_nud_state == NUD_FAILED) {
    LOG(WARNING) << "Neighbor becomes NUD_FAILED from "
                 << NUDStateToString(old_nud_state) << " on " << ifname_ << " "
                 << it->second.ToString();
  }

  // NUD_REACHABLE indicates the bidirectional reachability has been confirmed.
  constexpr auto kReachableState = WatchingEntry::ReachabilityState::kReachable;
  if (new_nud_state == NUD_REACHABLE &&
      it->second.reachability_state != kReachableState) {
    it->second.reachability_state = kReachableState;
    neighbor_event_handler_->Run(ifindex_, it->second.addr, it->second.role,
                                 NeighborReachabilityEventSignal::REACHABLE);
    return;
  }

  // NUD_FAILED indicates we have a reachability issue now.
  constexpr auto kFailedState = WatchingEntry::ReachabilityState::kFailed;
  if (new_nud_state == NUD_FAILED &&
      it->second.reachability_state != kFailedState) {
    it->second.reachability_state = kFailedState;
    neighbor_event_handler_->Run(ifindex_, it->second.addr, it->second.role,
                                 NeighborReachabilityEventSignal::FAILED);
    return;
  }
}

NetworkMonitorService::NetworkMonitorService(
    ShillClient* shill_client,
    const NeighborLinkMonitor::NeighborReachabilityEventHandler&
        neighbor_event_handler)
    : neighbor_event_handler_(neighbor_event_handler),
      shill_client_(shill_client),
      rtnl_handler_(shill::RTNLHandler::GetInstance()) {}

void NetworkMonitorService::Start() {
  // Setups the RTNL socket and listens to neighbor events. This should be
  // called before creating NeighborLinkMonitors.
  rtnl_handler_->Start(RTMGRP_NEIGH);

  // Calls ScanDevices() first to make sure ShillClient knows all existing
  // shill Devices, and then triggers OnShillDevicesChanged() manually before
  // registering DevicesChangedHandler to make sure we see each shill Device
  // exactly once.
  shill_client_->ScanDevices();
  OnShillDevicesChanged(shill_client_->get_interfaces(), {} /* removed */);
  shill_client_->RegisterDevicesChangedHandler(
      base::BindRepeating(&NetworkMonitorService::OnShillDevicesChanged,
                          weak_factory_.GetWeakPtr()));

  shill_client_->RegisterIPConfigsChangedHandler(base::BindRepeating(
      &NetworkMonitorService::OnIPConfigsChanged, weak_factory_.GetWeakPtr()));
}

void NetworkMonitorService::OnShillDevicesChanged(
    const std::vector<std::string>& added,
    const std::vector<std::string>& removed) {
  for (const auto& ifname : added) {
    ShillClient::Device device_props;
    if (!shill_client_->GetDeviceProperties(ifname, &device_props)) {
      LOG(ERROR)
          << "Get device props failed. Skipped creating neighbor monitor on "
          << ifname;
      continue;
    }

    if (device_props.type != ShillClient::Device::Type::kWifi) {
      LOG(INFO) << "Skipped creating neighbor monitor for interface " << ifname;
      continue;
    }

    int ifindex = if_nametoindex(device_props.ifname.c_str());
    if (ifindex == 0) {
      PLOG(ERROR) << "Could not obtain interface index for "
                  << device_props.ifname;
      continue;
    }

    auto link_monitor = std::make_unique<NeighborLinkMonitor>(
        ifindex, device_props.ifname, rtnl_handler_, &neighbor_event_handler_);
    link_monitor->OnIPConfigChanged(device_props.ipconfig);
    neighbor_link_monitors_[ifname] = std::move(link_monitor);
  }

  for (const auto& ifname : removed)
    neighbor_link_monitors_.erase(ifname);
}

void NetworkMonitorService::OnIPConfigsChanged(
    const std::string& ifname, const ShillClient::IPConfig& ipconfig) {
  const auto it = neighbor_link_monitors_.find(ifname);
  if (it == neighbor_link_monitors_.end())
    return;

  it->second->OnIPConfigChanged(ipconfig);
}

}  // namespace patchpanel
