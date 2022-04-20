// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_PPP_DEVICE_H_
#define SHILL_PPP_DEVICE_H_

#include <map>
#include <string>

#include "shill/ipconfig.h"
#include "shill/virtual_device.h"

namespace shill {

// Declared in the header to avoid linking unused code into shims.
static const char kPPPDNS1[] = "DNS1";
static const char kPPPDNS2[] = "DNS2";
static const char kPPPExternalIP4Address[] = "EXTERNAL_IP4_ADDRESS";
static const char kPPPGatewayAddress[] = "GATEWAY_ADDRESS";
static const char kPPPInterfaceName[] = "INTERNAL_IFNAME";
static const char kPPPInternalIP4Address[] = "INTERNAL_IP4_ADDRESS";
static const char kPPPLNSAddress[] = "LNS_ADDRESS";
static const char kPPPMRU[] = "MRU";
static const char kPPPExitStatus[] = "EXIT_STATUS";
static const char kPPPReasonAuthenticated[] = "authenticated";
static const char kPPPReasonAuthenticating[] = "authenticating";
static const char kPPPReasonConnect[] = "connect";
static const char kPPPReasonDisconnect[] = "disconnect";
static const char kPPPReasonExit[] = "exit";

class PPPDevice : public VirtualDevice {
 public:
  PPPDevice(Manager* manager,
            const std::string& link_name,
            int interface_index);
  PPPDevice(const PPPDevice&) = delete;
  PPPDevice& operator=(const PPPDevice&) = delete;

  ~PPPDevice() override;

  // Set IPConfig for this device, based on the dictionary of
  // configuration strings received from our PPP plugin. This also
  // ensures that the Connection for this device will have routing rules
  // sending traffic with matching source addresses to the per-device
  // routing table.
  virtual void UpdateIPConfigFromPPP(
      const std::map<std::string, std::string>& configuration,
      bool blackhole_ipv6);

  // Return an IPConfig::Properties struct parsed from |configuration|,
  // but don't set the IPConfig.  This lets the caller tweak or inspect
  // the Properties first.
  static IPConfig::Properties ParseIPConfiguration(
      const std::map<std::string, std::string>& configuration);

  static Service::ConnectFailure ExitStatusToFailure(int exit);

  // Get the failure reason from the dictionary which is received from our PPP
  // plugin and contains the exit status.
  static Service::ConnectFailure ParseExitFailure(
      const std::map<std::string, std::string>& dict);

  // Get the network device name (e.g. "ppp0") from the dictionary of
  // configuration strings received from our PPP plugin.
  static std::string GetInterfaceName(
      const std::map<std::string, std::string>& configuration);

 private:
  FRIEND_TEST(PPPDeviceTest, GetInterfaceName);
};

}  // namespace shill

#endif  // SHILL_PPP_DEVICE_H_
