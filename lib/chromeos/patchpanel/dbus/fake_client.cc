// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dbus/fake_client.h"

namespace patchpanel {

void FakeClient::RegisterOnAvailableCallback(
    base::RepeatingCallback<void(bool)> callback) {}

void FakeClient::RegisterProcessChangedCallback(
    base::RepeatingCallback<void(bool)> callback) {}

bool FakeClient::NotifyArcStartup(pid_t) {
  return true;
}

bool FakeClient::NotifyArcShutdown() {
  return true;
}

std::vector<NetworkDevice> FakeClient::NotifyArcVmStartup(uint32_t cid) {
  return {};
}

bool FakeClient::NotifyArcVmShutdown(uint32_t cid) {
  return true;
}

bool FakeClient::NotifyTerminaVmStartup(uint32_t cid,
                                        NetworkDevice* device,
                                        IPv4Subnet* container_subnet) {
  return true;
}

bool FakeClient::NotifyTerminaVmShutdown(uint32_t cid) {
  return true;
}

bool FakeClient::NotifyPluginVmStartup(uint64_t vm_id,
                                       int subnet_index,
                                       NetworkDevice* device) {
  return true;
}

bool FakeClient::NotifyPluginVmShutdown(uint64_t vm_id) {
  return true;
}

bool FakeClient::DefaultVpnRouting(int socket) {
  return true;
}

bool FakeClient::RouteOnVpn(int socket) {
  return true;
}

bool FakeClient::BypassVpn(int socket) {
  return true;
}

std::pair<base::ScopedFD, patchpanel::ConnectNamespaceResponse>
FakeClient::ConnectNamespace(pid_t pid,
                             const std::string& outbound_ifname,
                             bool forward_user_traffic,
                             bool route_on_vpn,
                             TrafficCounter::Source traffic_source) {
  return {};
}

void FakeClient::GetTrafficCounters(const std::set<std::string>& devices,
                                    GetTrafficCountersCallback callback) {
  if (devices.size() == 0) {
    std::move(callback).Run(
        {stored_traffic_counters_.begin(), stored_traffic_counters_.end()});
    return;
  }

  std::vector<TrafficCounter> return_counters;
  for (const auto& counter : stored_traffic_counters_) {
    if (devices.find(counter.device()) != devices.end())
      return_counters.push_back(counter);
  }

  std::move(callback).Run({return_counters.begin(), return_counters.end()});
}

bool FakeClient::ModifyPortRule(
    patchpanel::ModifyPortRuleRequest::Operation op,
    patchpanel::ModifyPortRuleRequest::RuleType type,
    patchpanel::ModifyPortRuleRequest::Protocol proto,
    const std::string& input_ifname,
    const std::string& input_dst_ip,
    uint32_t input_dst_port,
    const std::string& dst_ip,
    uint32_t dst_port) {
  return true;
}

bool FakeClient::SetVpnLockdown(bool enable) {
  return true;
}

base::ScopedFD FakeClient::RedirectDns(
    patchpanel::SetDnsRedirectionRuleRequest::RuleType type,
    const std::string& input_ifname,
    const std::string& proxy_address,
    const std::vector<std::string>& nameservers) {
  return {};
}

std::vector<NetworkDevice> FakeClient::GetDevices() {
  return {};
}

void FakeClient::RegisterNetworkDeviceChangedSignalHandler(
    NetworkDeviceChangedSignalHandler handler) {
  network_device_changed_handler_ = handler;
}

void FakeClient::RegisterNeighborReachabilityEventHandler(
    NeighborReachabilityEventHandler handler) {
  neighbor_handlers_.push_back(handler);
}

void FakeClient::TriggerNeighborReachabilityEvent(
    const NeighborReachabilityEventSignal& signal) {
  for (const auto& handler : neighbor_handlers_)
    handler.Run(signal);
}

}  // namespace patchpanel
