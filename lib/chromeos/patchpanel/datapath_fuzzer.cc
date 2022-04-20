// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>

#include <memory>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "patchpanel/datapath.h"
#include "patchpanel/firewall.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/multicast_forwarder.h"
#include "patchpanel/net_util.h"
#include "patchpanel/subnet.h"
#include "patchpanel/system.h"

namespace patchpanel {
namespace {

// Always succeeds
class FakeProcessRunner : public MinijailedProcessRunner {
 public:
  FakeProcessRunner() = default;
  FakeProcessRunner(const FakeProcessRunner&) = delete;
  FakeProcessRunner& operator=(const FakeProcessRunner&) = delete;
  ~FakeProcessRunner() = default;

  int Run(const std::vector<std::string>& argv, bool log_failures) override {
    return 0;
  }

  int RunSync(const std::vector<std::string>& argv,
              bool log_failures,
              std::string* output) override {
    return 0;
  }
};

// Always succeeds
class NoopSystem : public System {
 public:
  NoopSystem() = default;
  NoopSystem(const NoopSystem&) = delete;
  NoopSystem& operator=(const NoopSystem&) = delete;
  virtual ~NoopSystem() = default;

  int Ioctl(int fd, ioctl_req_t request, const char* argp) override {
    return 0;
  }
};

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
  base::AtExitManager at_exit;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider provider(data, size);

  uint32_t pid = provider.ConsumeIntegral<uint32_t>();
  std::string netns_name = provider.ConsumeRandomLengthString(10);
  std::string ifname = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string ifname2 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string ifname3 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string bridge = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  uint32_t addr = provider.ConsumeIntegral<uint32_t>();
  std::string addr_str = IPv4AddressToString(addr);
  uint32_t prefix_len = provider.ConsumeIntegralInRange<uint32_t>(0, 31);
  SubnetAddress subnet_addr(provider.ConsumeIntegral<int32_t>(), prefix_len,
                            base::DoNothing());
  MacAddress mac;
  std::vector<uint8_t> mac_addr_bytes =
      provider.ConsumeBytes<uint8_t>(mac.size());
  std::copy(mac_addr_bytes.begin(), mac_addr_bytes.end(), mac.begin());

  struct in6_addr ipv6_addr;
  memset(&ipv6_addr, 0, sizeof(ipv6_addr));
  std::vector<uint8_t> ipv6_addr_bytes =
      provider.ConsumeBytes<uint8_t>(sizeof(ipv6_addr.s6_addr));
  std::copy(ipv6_addr_bytes.begin(), ipv6_addr_bytes.end(), ipv6_addr.s6_addr);
  std::string ipv6_addr_str = IPv6AddressToString(ipv6_addr);
  bool route_on_vpn = provider.ConsumeBool();

  ConnectedNamespace nsinfo = {};
  nsinfo.pid = pid;
  nsinfo.netns_name = netns_name;
  nsinfo.source = TrafficSource::USER;
  nsinfo.outbound_ifname = ifname;
  nsinfo.route_on_vpn = route_on_vpn;
  nsinfo.host_ifname = ifname2;
  nsinfo.peer_ifname = ifname3;
  nsinfo.peer_subnet =
      std::make_unique<Subnet>(addr, prefix_len, base::DoNothing());
  nsinfo.peer_mac_addr = mac;

  auto runner = new FakeProcessRunner();
  auto firewall = new Firewall();
  NoopSystem system;
  Datapath datapath(runner, firewall, &system);
  datapath.Start();
  datapath.Stop();
  datapath.NetnsAttachName(netns_name, pid);
  datapath.NetnsDeleteName(netns_name);
  datapath.AddBridge(ifname, addr, prefix_len);
  datapath.RemoveBridge(ifname);
  datapath.AddToBridge(ifname, ifname2);
  datapath.StartRoutingDevice(ifname, ifname2, addr, TrafficSource::UNKNOWN,
                              route_on_vpn);
  datapath.StopRoutingDevice(ifname, ifname2, addr, TrafficSource::UNKNOWN,
                             route_on_vpn);
  datapath.StartRoutingNamespace(nsinfo);
  datapath.StopRoutingNamespace(nsinfo);
  datapath.ConnectVethPair(pid, netns_name, ifname, ifname2, mac, addr,
                           prefix_len, provider.ConsumeBool());
  datapath.RemoveInterface(ifname);
  datapath.AddTAP(ifname, &mac, &subnet_addr, "");
  datapath.RemoveTAP(ifname);
  datapath.AddIPv4Route(provider.ConsumeIntegral<uint32_t>(),
                        provider.ConsumeIntegral<uint32_t>(),
                        provider.ConsumeIntegral<uint32_t>());
  datapath.StartConnectionPinning(ifname);
  datapath.StopConnectionPinning(ifname);
  datapath.StartVpnRouting(ifname);
  datapath.StopVpnRouting(ifname);
  datapath.MaskInterfaceFlags(ifname, provider.ConsumeIntegral<uint16_t>(),
                              provider.ConsumeIntegral<uint16_t>());
  datapath.AddIPv6HostRoute(ifname, ipv6_addr_str, prefix_len);
  datapath.RemoveIPv6HostRoute(ifname, ipv6_addr_str, prefix_len);
  datapath.AddIPv6Address(ifname, ipv6_addr_str);
  datapath.RemoveIPv6Address(ifname, ipv6_addr_str);

  return 0;
}

}  // namespace
}  // namespace patchpanel
