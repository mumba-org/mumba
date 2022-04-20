// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/arc_vpn_driver.h"

#include <fcntl.h>
#include <unistd.h>

#include <iterator>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/connection.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/static_ip_parameters.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
static std::string ObjectID(const ArcVpnDriver* v) {
  return "(arc_vpn_driver)";
}
}  // namespace Logging

const VPNDriver::Property ArcVpnDriver::kProperties[] = {
    {kProviderHostProperty, 0},
    {kProviderTypeProperty, 0},
    {kArcVpnTunnelChromeProperty, 0}};

ArcVpnDriver::ArcVpnDriver(Manager* manager, ProcessManager* process_manager)
    : VPNDriver(manager, process_manager, kProperties, std::size(kProperties)) {
}

base::TimeDelta ArcVpnDriver::ConnectAsync(EventHandler* handler) {
  SLOG(this, 2) << __func__;
  // Nothing to do here since ARC already finish connecting to VPN
  // before Chrome calls Service::OnConnect. Just return success.
  metrics()->SendEnumToUMA(Metrics::kMetricVpnDriver, Metrics::kVpnDriverArc,
                           Metrics::kMetricVpnDriverMax);
  dispatcher()->PostTask(FROM_HERE,
                         base::BindOnce(&ArcVpnDriver::InvokeEventHandler,
                                        weak_factory_.GetWeakPtr(), handler));
  return kTimeoutNone;
}

void ArcVpnDriver::InvokeEventHandler(EventHandler* handler) {
  std::string if_name = VPNProvider::kArcBridgeIfName;
  int if_index = manager()->device_info()->GetIndex(if_name);
  if (if_index == -1) {
    handler->OnDriverFailure(Service::kFailureInternal,
                             "Failed to get interface index for arc bridge");
    return;
  }

  handler->OnDriverConnected(if_name, if_index);
}

void ArcVpnDriver::Disconnect() {
  SLOG(this, 2) << __func__;
}

void ArcVpnDriver::OnConnectTimeout() {
  NOTREACHED();
}

IPConfig::Properties ArcVpnDriver::GetIPProperties() const {
  SLOG(this, 2) << __func__;
  // Currently L3 settings for ARC VPN are set from Chrome as
  // StaticIPProperty before connecting, so this will be mostly empty.
  IPConfig::Properties ip_properties;
  // ARC always sets IncludedRoutes through StaticIPConfig.
  ip_properties.default_route = false;
  // IPv6 is not currently supported.  If the VPN is enabled, block all
  // IPv6 traffic so there is no "leak" past the VPN.
  ip_properties.blackhole_ipv6 = true;
  ip_properties.method = kTypeVPN;
  return ip_properties;
}

std::string ArcVpnDriver::GetProviderType() const {
  return std::string(kProviderArcVpn);
}

}  // namespace shill
