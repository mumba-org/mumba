// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DBUS_FAKE_CLIENT_H_
#define PATCHPANEL_DBUS_FAKE_CLIENT_H_

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "patchpanel/dbus/client.h"

namespace patchpanel {

// Fake implementation of patchpanel::ClientInterface which can be used in
// tests.
class BRILLO_EXPORT FakeClient : public Client {
 public:
  FakeClient() = default;
  ~FakeClient() = default;

  // Client overrides.
  void RegisterOnAvailableCallback(
      base::RepeatingCallback<void(bool)> callback) override;
  void RegisterProcessChangedCallback(
      base::RepeatingCallback<void(bool)> callback) override;

  bool NotifyArcStartup(pid_t pid) override;
  bool NotifyArcShutdown() override;

  std::vector<NetworkDevice> NotifyArcVmStartup(uint32_t cid) override;
  bool NotifyArcVmShutdown(uint32_t cid) override;

  bool NotifyTerminaVmStartup(uint32_t cid,
                              NetworkDevice* device,
                              IPv4Subnet* container_subnet) override;
  bool NotifyTerminaVmShutdown(uint32_t cid) override;

  bool NotifyPluginVmStartup(uint64_t vm_id,
                             int subnet_index,
                             NetworkDevice* device) override;
  bool NotifyPluginVmShutdown(uint64_t vm_id) override;

  bool DefaultVpnRouting(int socket) override;

  bool RouteOnVpn(int socket) override;

  bool BypassVpn(int socket) override;

  std::pair<base::ScopedFD, patchpanel::ConnectNamespaceResponse>
  ConnectNamespace(pid_t pid,
                   const std::string& outbound_ifname,
                   bool forward_user_traffic,
                   bool route_on_vpn,
                   TrafficCounter::Source traffic_source) override;

  void GetTrafficCounters(const std::set<std::string>& devices,
                          GetTrafficCountersCallback callback) override;

  bool ModifyPortRule(patchpanel::ModifyPortRuleRequest::Operation op,
                      patchpanel::ModifyPortRuleRequest::RuleType type,
                      patchpanel::ModifyPortRuleRequest::Protocol proto,
                      const std::string& input_ifname,
                      const std::string& input_dst_ip,
                      uint32_t input_dst_port,
                      const std::string& dst_ip,
                      uint32_t dst_port) override;

  bool SetVpnLockdown(bool enable) override;

  base::ScopedFD RedirectDns(
      patchpanel::SetDnsRedirectionRuleRequest::RuleType type,
      const std::string& input_ifname,
      const std::string& proxy_address,
      const std::vector<std::string>& nameservers) override;

  std::vector<NetworkDevice> GetDevices() override;

  void RegisterNetworkDeviceChangedSignalHandler(
      NetworkDeviceChangedSignalHandler handler) override;

  void RegisterNeighborReachabilityEventHandler(
      NeighborReachabilityEventHandler handler) override;

  // Triggers registered handlers for NeighborReachabilityEventSignal.
  void TriggerNeighborReachabilityEvent(
      const NeighborReachabilityEventSignal& signal);

  void set_stored_traffic_counters(
      const std::vector<TrafficCounter>& counters) {
    stored_traffic_counters_ = counters;
  }

 private:
  std::vector<TrafficCounter> stored_traffic_counters_;
  std::vector<NeighborReachabilityEventHandler> neighbor_handlers_;
  NetworkDeviceChangedSignalHandler network_device_changed_handler_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_DBUS_FAKE_CLIENT_H_
