// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ppp_device.h"

#include <map>
#include <string>

#include <base/containers/contains.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

extern "C" {
// A struct member in pppd.h has the name 'class'.
#define class class_num
// pppd.h defines a bool type.
#define bool pppd_bool_t
#include <pppd/pppd.h>
#undef bool
#undef class
}

#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/technology.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kPPP;
static std::string ObjectID(const PPPDevice* p) {
  return p->link_name();
}
}  // namespace Logging

PPPDevice::PPPDevice(Manager* manager,
                     const std::string& link_name,
                     int interface_index)
    : VirtualDevice(manager, link_name, interface_index, Technology::kPPP) {}

PPPDevice::~PPPDevice() = default;

void PPPDevice::UpdateIPConfigFromPPP(
    const std::map<std::string, std::string>& configuration,
    bool blackhole_ipv6) {
  SLOG(this, 2) << __func__ << " on " << link_name();
  IPConfig::Properties properties = ParseIPConfiguration(configuration);
  properties.blackhole_ipv6 = blackhole_ipv6;
  properties.use_if_addrs = true;
  UpdateIPConfig(properties);
}

// static
std::string PPPDevice::GetInterfaceName(
    const std::map<std::string, std::string>& configuration) {
  if (base::Contains(configuration, kPPPInterfaceName)) {
    return configuration.find(kPPPInterfaceName)->second;
  }
  return std::string();
}

// static
IPConfig::Properties PPPDevice::ParseIPConfiguration(
    const std::map<std::string, std::string>& configuration) {
  IPConfig::Properties properties;
  properties.address_family = IPAddress::kFamilyIPv4;
  properties.subnet_prefix =
      IPAddress::GetMaxPrefixLength(properties.address_family);
  for (const auto& it : configuration) {
    const auto& key = it.first;
    const auto& value = it.second;
    SLOG(PPP, nullptr, 2) << "Processing: " << key << " -> " << value;
    if (key == kPPPInternalIP4Address) {
      properties.address = value;
    } else if (key == kPPPExternalIP4Address) {
      properties.peer_address = value;
    } else if (key == kPPPGatewayAddress) {
      properties.gateway = value;
    } else if (key == kPPPDNS1) {
      properties.dns_servers.insert(properties.dns_servers.begin(), value);
    } else if (key == kPPPDNS2) {
      properties.dns_servers.push_back(value);
    } else if (key == kPPPLNSAddress) {
      // This is really a L2TPIPsec property. But it's sent to us by
      // our PPP plugin.
      size_t prefix = IPAddress::GetMaxPrefixLength(properties.address_family);
      properties.exclusion_list.push_back(value + "/" +
                                          base::NumberToString(prefix));
    } else if (key == kPPPMRU) {
      int mru;
      if (!base::StringToInt(value, &mru)) {
        LOG(WARNING) << "Failed to parse MRU: " << value;
        continue;
      }
      properties.mtu = mru;
    } else {
      SLOG(PPP, nullptr, 2) << "Key ignored.";
    }
  }
  if (properties.gateway.empty()) {
    // The gateway may be unspecified, since this is a point-to-point
    // link. Set to the peer's address, so that Connection can set the
    // routing table.
    properties.gateway = properties.peer_address;
  }
  return properties;
}

// static
Service::ConnectFailure PPPDevice::ExitStatusToFailure(int exit) {
  switch (exit) {
    case EXIT_OK:
      return Service::kFailureNone;
    case EXIT_PEER_AUTH_FAILED:
    case EXIT_AUTH_TOPEER_FAILED:
      return Service::kFailurePPPAuth;
    default:
      return Service::kFailureUnknown;
  }
}

// static
Service::ConnectFailure PPPDevice::ParseExitFailure(
    const std::map<std::string, std::string>& dict) {
  const auto it = dict.find(kPPPExitStatus);
  if (it == dict.end()) {
    LOG(ERROR) << "Failed to find the failure status in the dict";
    return Service::kFailureInternal;
  }
  int exit = 0;
  if (!base::StringToInt(it->second, &exit)) {
    LOG(ERROR) << "Failed to parse the failure status from the dict, value: "
               << it->second;
    return Service::kFailureInternal;
  }
  return ExitStatusToFailure(exit);
}

}  // namespace shill
