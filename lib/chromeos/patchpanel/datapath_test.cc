// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/datapath.h"

#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/firewall.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/net_util.h"
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

using testing::_;
using testing::DoAll;
using testing::ElementsAre;
using testing::ElementsAreArray;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrEq;

namespace patchpanel {
namespace {

// TODO(hugobenichi) Centralize this constant definition
constexpr pid_t kTestPID = -2;

std::vector<std::string> SplitCommand(const std::string& command) {
  return base::SplitString(command, " ",
                           base::WhitespaceHandling::TRIM_WHITESPACE,
                           base::SplitResult::SPLIT_WANT_NONEMPTY);
}

using IpFamily::Dual;
using IpFamily::IPv4;
using IpFamily::IPv6;

class MockProcessRunner : public MinijailedProcessRunner {
 public:
  MockProcessRunner() = default;
  ~MockProcessRunner() = default;

  MOCK_METHOD4(ip,
               int(const std::string& obj,
                   const std::string& cmd,
                   const std::vector<std::string>& args,
                   bool log_failures));
  MOCK_METHOD4(ip6,
               int(const std::string& obj,
                   const std::string& cmd,
                   const std::vector<std::string>& args,
                   bool log_failures));
  MOCK_METHOD4(iptables,
               int(const std::string& table,
                   const std::vector<std::string>& argv,
                   bool log_failures,
                   std::string* output));
  MOCK_METHOD4(ip6tables,
               int(const std::string& table,
                   const std::vector<std::string>& argv,
                   bool log_failures,
                   std::string* output));
  MOCK_METHOD2(ip_netns_add,
               int(const std::string& netns_name, bool log_failures));
  MOCK_METHOD3(ip_netns_attach,
               int(const std::string& netns_name,
                   pid_t netns_pid,
                   bool log_failures));
  MOCK_METHOD2(ip_netns_delete,
               int(const std::string& netns_name, bool log_failures));
  MOCK_METHOD2(modprobe_all,
               int(const std::vector<std::string>& modules, bool log_failures));
};

class MockFirewall : public Firewall {
 public:
  MockFirewall() = default;
  ~MockFirewall() = default;

  MOCK_METHOD3(AddAcceptRules,
               bool(patchpanel::ModifyPortRuleRequest::Protocol protocol,
                    uint16_t port,
                    const std::string& interface));
  MOCK_METHOD3(DeleteAcceptRules,
               bool(Protocol protocol,
                    uint16_t port,
                    const std::string& interface));
  MOCK_METHOD2(AddLoopbackLockdownRules,
               bool(Protocol protocol, uint16_t port));
  MOCK_METHOD2(DeleteLoopbackLockdownRules,
               bool(Protocol protocol, uint16_t port));
  MOCK_METHOD6(AddIpv4ForwardRule,
               bool(Protocol protocol,
                    const std::string& input_ip,
                    uint16_t port,
                    const std::string& interface,
                    const std::string& dst_ip,
                    uint16_t dst_port));
  MOCK_METHOD6(DeleteIpv4ForwardRule,
               bool(Protocol protocol,
                    const std::string& input_ip,
                    uint16_t port,
                    const std::string& interface,
                    const std::string& dst_ip,
                    uint16_t dst_port));
};

class FakeSystem : public System {
 public:
  FakeSystem() = default;
  ~FakeSystem() = default;

  // Capture Ioctls operations and arguments. Always succeeds.
  int Ioctl(int fd, ioctl_req_t request, const char* argp) override {
    ioctl_reqs.push_back(request);
    switch (request) {
      case SIOCBRADDBR:
      case SIOCBRDELBR: {
        ioctl_ifreq_args.push_back({std::string(argp), {}});
        break;
      }
      case SIOCBRADDIF:
      case TUNSETIFF:
      case SIOCSIFADDR:
      case SIOCSIFNETMASK:
      case SIOCSIFHWADDR:
      case SIOCGIFFLAGS:
      case SIOCSIFFLAGS: {
        struct ifreq ifr;
        memcpy(&ifr, argp, sizeof(ifr));
        ioctl_ifreq_args.push_back({std::string(ifr.ifr_name), ifr});
        break;
      }
      case SIOCADDRT:
      case SIOCDELRT: {
        struct rtentry route;
        memcpy(&route, argp, sizeof(route));
        ioctl_rtentry_args.push_back({"", route});
        // Copy the string poited by rtentry.rt_dev because Add/DeleteIPv4Route
        // pass this value to ioctl() on the stack.
        if (route.rt_dev) {
          auto& cap = ioctl_rtentry_args.back();
          cap.first = std::string(route.rt_dev);
          cap.second.rt_dev = const_cast<char*>(cap.first.c_str());
        }
        break;
      }
      case TUNSETPERSIST:
      case TUNSETOWNER: {
        // ioctl_u32_args.push_back(static_cast<uint32_t>(argp));
        break;
      }
    }
    return 0;
  }

  MOCK_METHOD3(SysNetSet,
               bool(SysNet target,
                    const std::string& content,
                    const std::string& iface));
  MOCK_METHOD1(IfNametoindex, uint32_t(const std::string& ifname));

  std::vector<ioctl_req_t> ioctl_reqs;
  std::vector<std::pair<std::string, struct rtentry>> ioctl_rtentry_args;
  std::vector<std::pair<std::string, struct ifreq>> ioctl_ifreq_args;
  std::vector<uint32_t> ioctl_u32_args;
};

void Verify_ip(MockProcessRunner& runner, const std::string& command) {
  auto args = SplitCommand(command);
  const auto object = args[0];
  const auto action = args[1];
  args.erase(args.begin());
  args.erase(args.begin());
  EXPECT_CALL(runner,
              ip(StrEq(object), StrEq(action), ElementsAreArray(args), _));
}

void Verify_ip6(MockProcessRunner& runner, const std::string& command) {
  auto args = SplitCommand(command);
  const auto object = args[0];
  const auto action = args[1];
  args.erase(args.begin());
  args.erase(args.begin());
  EXPECT_CALL(runner,
              ip6(StrEq(object), StrEq(action), ElementsAreArray(args), _));
}

void Verify_iptables(MockProcessRunner& runner,
                     IpFamily family,
                     const std::string& command,
                     int call_count = 1) {
  auto args =
      base::SplitString(command, " ", base::WhitespaceHandling::TRIM_WHITESPACE,
                        base::SplitResult::SPLIT_WANT_NONEMPTY);
  const auto table = args[0];
  args.erase(args.begin());
  if (family & IPv4)
    EXPECT_CALL(runner,
                iptables(StrEq(table), ElementsAreArray(args), _, nullptr))
        .Times(call_count);
  if (family & IPv6)
    EXPECT_CALL(runner,
                ip6tables(StrEq(table), ElementsAreArray(args), _, nullptr))
        .Times(call_count);
}

void Verify_ip_netns_add(MockProcessRunner& runner,
                         const std::string& netns_name) {
  EXPECT_CALL(runner, ip_netns_add(StrEq(netns_name), _));
}

void Verify_ip_netns_attach(MockProcessRunner& runner,
                            const std::string& netns_name,
                            pid_t pid) {
  EXPECT_CALL(runner, ip_netns_attach(StrEq(netns_name), pid, _));
}

void Verify_ip_netns_delete(MockProcessRunner& runner,
                            const std::string& netns_name) {
  EXPECT_CALL(runner, ip_netns_delete(StrEq(netns_name), _));
}

}  // namespace

TEST(DatapathTest, IpFamily) {
  EXPECT_EQ(Dual, IPv4 | IPv6);
  EXPECT_EQ(Dual & IPv4, IPv4);
  EXPECT_EQ(Dual & IPv6, IPv6);
  EXPECT_NE(Dual, IPv4);
  EXPECT_NE(Dual, IPv6);
  EXPECT_NE(IPv4, IPv6);
}

TEST(DatapathTest, Start) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  // Asserts for sysctl modifications
  EXPECT_CALL(system, SysNetSet(System::SysNet::IPv4Forward, "1", ""));
  EXPECT_CALL(system,
              SysNetSet(System::SysNet::IPLocalPortRange, "32768 47103", ""));
  EXPECT_CALL(system, SysNetSet(System::SysNet::IPv6Forward, "1", ""));

  static struct {
    IpFamily family;
    std::string command;
    int call_count;
  } iptables_commands[] = {
      // Asserts for iptables chain reset.
      {Dual, "filter -D INPUT -j ingress_port_firewall -w"},
      {Dual, "filter -D OUTPUT -j egress_port_firewall -w"},
      {IPv4, "filter -D OUTPUT -j drop_guest_ipv4_prefix -w"},
      {Dual, "filter -D OUTPUT -j vpn_egress_filters -w"},
      {Dual, "filter -F FORWARD -w"},
      {Dual, "mangle -F FORWARD -w"},
      {Dual, "mangle -F INPUT -w"},
      {Dual, "mangle -F OUTPUT -w"},
      {Dual, "mangle -F POSTROUTING -w"},
      {Dual, "mangle -F PREROUTING -w"},
      {Dual,
       "mangle -D OUTPUT -m owner ! --uid-owner chronos -j skip_apply_vpn_mark "
       "-w"},
      {Dual, "mangle -L apply_local_source_mark -w"},
      {Dual, "mangle -F apply_local_source_mark -w"},
      {Dual, "mangle -X apply_local_source_mark -w"},
      {Dual, "mangle -L apply_vpn_mark -w"},
      {Dual, "mangle -F apply_vpn_mark -w"},
      {Dual, "mangle -X apply_vpn_mark -w"},
      {Dual, "mangle -L skip_apply_vpn_mark -w"},
      {Dual, "mangle -F skip_apply_vpn_mark -w"},
      {Dual, "mangle -X skip_apply_vpn_mark -w"},
      {IPv4, "filter -L drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -F drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -X drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -L drop_guest_invalid_ipv4 -w"},
      {IPv4, "filter -F drop_guest_invalid_ipv4 -w"},
      {IPv4, "filter -X drop_guest_invalid_ipv4 -w"},
      {Dual, "filter -L vpn_egress_filters -w"},
      {Dual, "filter -F vpn_egress_filters -w"},
      {Dual, "filter -X vpn_egress_filters -w"},
      {Dual, "filter -L vpn_accept -w"},
      {Dual, "filter -F vpn_accept -w"},
      {Dual, "filter -X vpn_accept -w"},
      {Dual, "filter -L vpn_lockdown -w"},
      {Dual, "filter -F vpn_lockdown -w"},
      {Dual, "filter -X vpn_lockdown -w"},
      {IPv4, "nat -D PREROUTING -j ingress_port_forwarding -w"},
      {IPv4, "nat -D PREROUTING -j ingress_default_forwarding -w"},
      {Dual, "nat -D PREROUTING -j redirect_default_dns -w"},
      {Dual, "nat -D PREROUTING -j redirect_arc_dns -w"},
      {IPv4, "nat -L redirect_dns -w"},
      {IPv4, "nat -F redirect_dns -w"},
      {IPv4, "nat -X redirect_dns -w"},
      {IPv4, "nat -L ingress_default_forwarding -w"},
      {IPv4, "nat -F ingress_default_forwarding -w"},
      {IPv4, "nat -X ingress_default_forwarding -w"},
      {Dual, "nat -L redirect_default_dns -w"},
      {Dual, "nat -F redirect_default_dns -w"},
      {Dual, "nat -X redirect_default_dns -w"},
      {Dual, "nat -L redirect_arc_dns -w"},
      {Dual, "nat -F redirect_arc_dns -w"},
      {Dual, "nat -X redirect_arc_dns -w"},
      {Dual, "nat -L redirect_chrome_dns -w"},
      {Dual, "nat -F redirect_chrome_dns -w"},
      {Dual, "nat -X redirect_chrome_dns -w"},
      {Dual, "nat -L redirect_user_dns -w"},
      {Dual, "nat -F redirect_user_dns -w"},
      {Dual, "nat -X redirect_user_dns -w"},
      {Dual, "nat -L snat_chrome_dns -w"},
      {Dual, "nat -F snat_chrome_dns -w"},
      {Dual, "nat -X snat_chrome_dns -w"},
      {IPv6, "nat -L snat_user_dns -w"},
      {IPv6, "nat -F snat_user_dns -w"},
      {IPv6, "nat -X snat_user_dns -w"},
      {IPv4, "nat -F POSTROUTING -w"},
      {Dual, "nat -F OUTPUT -w"},
      // Asserts for SNAT rules of traffic forwarded from downstream interfaces.
      {IPv4, "filter -N drop_guest_invalid_ipv4 -w"},
      {IPv4, "filter -I FORWARD -j drop_guest_invalid_ipv4 -w"},
      {IPv4,
       "filter -I drop_guest_invalid_ipv4 -m mark --mark 0x00000001/0x00000001 "
       "-m state "
       "--state INVALID -j DROP "
       "-w"},
      {IPv4,
       "filter -I drop_guest_invalid_ipv4 -s 100.115.92.0/23 -p tcp "
       "--tcp-flags FIN,PSH "
       "FIN,PSH -o rmnet+ -j DROP -w"},
      {IPv4,
       "filter -I drop_guest_invalid_ipv4 -s 100.115.92.0/23 -p tcp "
       "--tcp-flags FIN,PSH "
       "FIN,PSH -o wwan+ -j DROP -w"},
      {IPv4,
       "nat -A POSTROUTING -m mark --mark 0x00000001/0x00000001 -j MASQUERADE "
       "-w"},
      // Asserts for AddForwardEstablishedRule
      {IPv4,
       "filter -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT -w"},
      // Asserts for AddSourceIPv4DropRule() calls.
      {IPv4, "filter -N drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -I OUTPUT -j drop_guest_ipv4_prefix -w"},
      {IPv4,
       "filter -I drop_guest_ipv4_prefix -o eth+ -s 100.115.92.0/23 -j DROP "
       "-w"},
      {IPv4,
       "filter -I drop_guest_ipv4_prefix -o wlan+ -s 100.115.92.0/23 -j DROP "
       "-w"},
      {IPv4,
       "filter -I drop_guest_ipv4_prefix -o mlan+ -s 100.115.92.0/23 -j DROP "
       "-w"},
      {IPv4,
       "filter -I drop_guest_ipv4_prefix -o usb+ -s 100.115.92.0/23 -j DROP "
       "-w"},
      {IPv4,
       "filter -I drop_guest_ipv4_prefix -o wwan+ -s 100.115.92.0/23 -j DROP "
       "-w"},
      {IPv4,
       "filter -I drop_guest_ipv4_prefix -o rmnet+ -s 100.115.92.0/23 -j DROP "
       "-w"},
      // Asserts for forwarding ICMP6.
      {IPv6, "filter -A FORWARD -p ipv6-icmp -j ACCEPT -w"},
      // Asserts for OUTPUT ndp connmark bypass rule
      {IPv6,
       "mangle -I OUTPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT "
       "-w"},
      {IPv6,
       "mangle -I OUTPUT -p icmpv6 --icmpv6-type router-advertisement -j "
       "ACCEPT -w"},
      {IPv6,
       "mangle -I OUTPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j "
       "ACCEPT -w"},
      {IPv6,
       "mangle -I OUTPUT -p icmpv6 --icmpv6-type neighbour-advertisement -j "
       "ACCEPT -w"},
      // Asserts for OUTPUT CONNMARK restore rule
      {Dual,
       "mangle -A OUTPUT -j CONNMARK --restore-mark --mask 0xffff0000 -w"},
      // Asserts for apply_local_source_mark chain
      {Dual, "mangle -N apply_local_source_mark -w"},
      {Dual, "mangle -A OUTPUT -j apply_local_source_mark -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m mark ! --mark 0x0/0x00003f00 -j "
       "RETURN -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner chronos -j MARK "
       "--set-mark 0x00008100/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner debugd -j MARK "
       "--set-mark 0x00008200/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner cups -j MARK "
       "--set-mark 0x00008200/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner lpadmin -j MARK "
       "--set-mark 0x00008200/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner kerberosd -j "
       "MARK --set-mark 0x00008400/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner kerberosd-exec "
       "-j MARK --set-mark 0x00008400/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner tlsdate -j MARK "
       "--set-mark 0x00008400/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner pluginvm -j "
       "MARK --set-mark 0x00008200/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m owner --uid-owner fuse-smbfs -j "
       "MARK --set-mark 0x00008400/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m cgroup --cgroup 0x00010001 -j "
       "MARK --set-mark 0x00000300/0x0000ff00 -w"},
      {Dual,
       "mangle -A apply_local_source_mark -m mark --mark 0x0/0x00003f00 -j "
       "MARK --set-mark 0x00000400/0x00003f00 -w"},
      // Asserts for apply_vpn_mark chain
      {Dual, "mangle -N apply_vpn_mark -w"},
      {Dual,
       "mangle -A OUTPUT -m mark --mark 0x00008000/0x0000c000 -j "
       "apply_vpn_mark -w"},
      // Asserts for redirect_dns chain creation
      {IPv4, "nat -N redirect_dns -w"},
      // Asserts for VPN filter chain creations
      {Dual, "filter -N vpn_egress_filters -w"},
      {Dual, "filter -I OUTPUT -j vpn_egress_filters -w"},
      {Dual, "filter -A FORWARD -j vpn_egress_filters -w"},
      {Dual, "filter -N vpn_lockdown -w"},
      {Dual, "filter -A vpn_egress_filters -j vpn_lockdown -w"},
      {Dual, "filter -N vpn_accept -w"},
      {Dual, "filter -A vpn_egress_filters -j vpn_accept -w"},
      // Asserts for DNS proxy rules
      {Dual, "mangle -N skip_apply_vpn_mark -w"},
      {Dual,
       "mangle -A OUTPUT -m owner ! --uid-owner chronos -j skip_apply_vpn_mark "
       "-w"},
      {IPv4, "nat -N ingress_default_forwarding -w"},
      {IPv4, "nat -N ingress_port_forwarding -w"},
      {IPv4, "nat -A PREROUTING -j ingress_default_forwarding -w"},
      {IPv4, "nat -A PREROUTING -j ingress_port_forwarding -w"},
      {Dual, "nat -N redirect_default_dns -w"},
      {Dual, "nat -N redirect_arc_dns -w"},
      {Dual, "nat -N redirect_chrome_dns -w"},
      {Dual, "nat -N redirect_user_dns -w"},
      {Dual, "nat -A PREROUTING -j redirect_default_dns -w"},
      {Dual, "nat -A PREROUTING -j redirect_arc_dns -w"},
      {Dual, "nat -A OUTPUT -j redirect_chrome_dns -w"},
      {Dual,
       "nat -A OUTPUT -m mark --mark 0x00008000/0x0000c000 -j "
       "redirect_user_dns -w"},
      {Dual, "nat -N snat_chrome_dns -w"},
      {IPv6, "nat -N snat_user_dns -w"},
      {Dual,
       "nat -A POSTROUTING -m mark --mark 0x00000100/0x00003f00 -j "
       "snat_chrome_dns -w"},
      {IPv6,
       "nat -A POSTROUTING -m mark --mark 0x00008000/0x0000c000 -j "
       "snat_user_dns -w"},
      // Asserts for egress and ingress port firewall chains
      {Dual, "filter -N ingress_port_firewall -w"},
      {Dual, "filter -A INPUT -j ingress_port_firewall -w"},
      {Dual, "filter -N egress_port_firewall -w"},
      {Dual, "filter -A OUTPUT -j egress_port_firewall -w"},
  };
  for (const auto& c : iptables_commands) {
    Verify_iptables(*runner, c.family, c.command);
  }

  Datapath datapath(runner, firewall, &system);
  datapath.Start();
}

TEST(DatapathTest, Stop) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  // Asserts for sysctl modifications
  EXPECT_CALL(system, SysNetSet(System::SysNet::IPv4Forward, "0", ""));
  EXPECT_CALL(system,
              SysNetSet(System::SysNet::IPLocalPortRange, "32768 61000", ""));
  EXPECT_CALL(system, SysNetSet(System::SysNet::IPv6Forward, "0", ""));
  // Asserts for iptables chain reset.
  std::vector<std::pair<IpFamily, std::string>> iptables_commands = {
      {IPv4, "filter -D OUTPUT -j drop_guest_ipv4_prefix -w"},
      {Dual, "filter -D OUTPUT -j vpn_egress_filters -w"},
      {Dual, "filter -F FORWARD -w"},
      {Dual, "mangle -F FORWARD -w"},
      {Dual, "mangle -F INPUT -w"},
      {Dual, "mangle -F OUTPUT -w"},
      {Dual, "mangle -F POSTROUTING -w"},
      {Dual, "mangle -F PREROUTING -w"},
      {Dual,
       "mangle -D OUTPUT -m owner ! --uid-owner chronos -j skip_apply_vpn_mark "
       "-w"},
      {Dual, "mangle -L apply_local_source_mark -w"},
      {Dual, "mangle -F apply_local_source_mark -w"},
      {Dual, "mangle -X apply_local_source_mark -w"},
      {Dual, "mangle -L apply_vpn_mark -w"},
      {Dual, "mangle -F apply_vpn_mark -w"},
      {Dual, "mangle -X apply_vpn_mark -w"},
      {Dual, "mangle -L skip_apply_vpn_mark -w"},
      {Dual, "mangle -F skip_apply_vpn_mark -w"},
      {Dual, "mangle -X skip_apply_vpn_mark -w"},
      {IPv4, "filter -L drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -F drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -X drop_guest_ipv4_prefix -w"},
      {IPv4, "filter -L drop_guest_invalid_ipv4 -w"},
      {IPv4, "filter -F drop_guest_invalid_ipv4 -w"},
      {IPv4, "filter -X drop_guest_invalid_ipv4 -w"},
      {Dual, "filter -L vpn_egress_filters -w"},
      {Dual, "filter -F vpn_egress_filters -w"},
      {Dual, "filter -X vpn_egress_filters -w"},
      {Dual, "filter -L vpn_accept -w"},
      {Dual, "filter -F vpn_accept -w"},
      {Dual, "filter -X vpn_accept -w"},
      {Dual, "filter -L vpn_lockdown -w"},
      {Dual, "filter -F vpn_lockdown -w"},
      {Dual, "filter -X vpn_lockdown -w"},
      {Dual, "filter -D INPUT -j ingress_port_firewall -w"},
      {Dual, "filter -D OUTPUT -j egress_port_firewall -w"},
      {IPv4, "nat -D PREROUTING -j ingress_port_forwarding -w"},
      {IPv4, "nat -D PREROUTING -j ingress_default_forwarding -w"},
      {Dual, "nat -D PREROUTING -j redirect_default_dns -w"},
      {Dual, "nat -D PREROUTING -j redirect_arc_dns -w"},
      {IPv4, "nat -L redirect_dns -w"},
      {IPv4, "nat -F redirect_dns -w"},
      {IPv4, "nat -X redirect_dns -w"},
      {IPv4, "nat -L ingress_default_forwarding -w"},
      {IPv4, "nat -F ingress_default_forwarding -w"},
      {IPv4, "nat -X ingress_default_forwarding -w"},
      {Dual, "nat -L redirect_default_dns -w"},
      {Dual, "nat -F redirect_default_dns -w"},
      {Dual, "nat -X redirect_default_dns -w"},
      {Dual, "nat -L redirect_arc_dns -w"},
      {Dual, "nat -F redirect_arc_dns -w"},
      {Dual, "nat -X redirect_arc_dns -w"},
      {Dual, "nat -L redirect_chrome_dns -w"},
      {Dual, "nat -F redirect_chrome_dns -w"},
      {Dual, "nat -X redirect_chrome_dns -w"},
      {Dual, "nat -L redirect_user_dns -w"},
      {Dual, "nat -F redirect_user_dns -w"},
      {Dual, "nat -X redirect_user_dns -w"},
      {Dual, "nat -L snat_chrome_dns -w"},
      {Dual, "nat -F snat_chrome_dns -w"},
      {Dual, "nat -X snat_chrome_dns -w"},
      {IPv6, "nat -L snat_user_dns -w"},
      {IPv6, "nat -F snat_user_dns -w"},
      {IPv6, "nat -X snat_user_dns -w"},
      {IPv4, "nat -F POSTROUTING -w"},
      {Dual, "nat -F OUTPUT -w"},
  };
  for (const auto& c : iptables_commands) {
    Verify_iptables(*runner, c.first, c.second);
  }

  Datapath datapath(runner, firewall, &system);
  datapath.Stop();
}

TEST(DatapathTest, AddTAP) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Datapath datapath(runner, firewall, &system);
  MacAddress mac = {1, 2, 3, 4, 5, 6};
  Subnet subnet(Ipv4Addr(100, 115, 92, 4), 30, base::DoNothing());
  auto addr = subnet.AllocateAtOffset(0);
  auto ifname = datapath.AddTAP("foo0", &mac, addr.get(), "");

  EXPECT_EQ(ifname, "foo0");
  std::vector<ioctl_req_t> expected = {
      TUNSETIFF,     TUNSETPERSIST, SIOCSIFADDR, SIOCSIFNETMASK,
      SIOCSIFHWADDR, SIOCGIFFLAGS,  SIOCSIFFLAGS};
  EXPECT_EQ(system.ioctl_reqs, expected);
}

TEST(DatapathTest, AddTAPWithOwner) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Datapath datapath(runner, firewall, &system);
  MacAddress mac = {1, 2, 3, 4, 5, 6};
  Subnet subnet(Ipv4Addr(100, 115, 92, 4), 30, base::DoNothing());
  auto addr = subnet.AllocateAtOffset(0);
  auto ifname = datapath.AddTAP("foo0", &mac, addr.get(), "root");

  EXPECT_EQ(ifname, "foo0");
  std::vector<ioctl_req_t> expected = {
      TUNSETIFF,      TUNSETPERSIST, TUNSETOWNER,  SIOCSIFADDR,
      SIOCSIFNETMASK, SIOCSIFHWADDR, SIOCGIFFLAGS, SIOCSIFFLAGS};
  EXPECT_EQ(system.ioctl_reqs, expected);
}

TEST(DatapathTest, AddTAPNoAddrs) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Datapath datapath(runner, firewall, &system);
  auto ifname = datapath.AddTAP("foo0", nullptr, nullptr, "");

  EXPECT_EQ(ifname, "foo0");
  std::vector<ioctl_req_t> expected = {TUNSETIFF, TUNSETPERSIST, SIOCGIFFLAGS,
                                       SIOCSIFFLAGS};
  EXPECT_EQ(system.ioctl_reqs, expected);
}

TEST(DatapathTest, RemoveTAP) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip(*runner, "tuntap del foo0 mode tap");
  Datapath datapath(runner, firewall, &system);
  datapath.RemoveTAP("foo0");
}

TEST(DatapathTest, NetnsAttachName) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip_netns_delete(*runner, "netns_foo");
  Verify_ip_netns_attach(*runner, "netns_foo", 1234);
  Datapath datapath(runner, firewall, &system);
  EXPECT_TRUE(datapath.NetnsAttachName("netns_foo", 1234));
}

TEST(DatapathTest, NetnsDeleteName) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  EXPECT_CALL(*runner, ip_netns_delete(StrEq("netns_foo"), true));
  Datapath datapath(runner, firewall, &system);
  EXPECT_TRUE(datapath.NetnsDeleteName("netns_foo"));
}

TEST(DatapathTest, AddBridge) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_ip(*runner, "addr add 1.1.1.1/30 brd 1.1.1.3 dev br");
  Verify_ip(*runner, "link set br up");

  Datapath datapath(runner, firewall, &system);
  datapath.AddBridge("br", Ipv4Addr(1, 1, 1, 1), 30);

  EXPECT_EQ(1, system.ioctl_reqs.size());
  EXPECT_EQ(SIOCBRADDBR, system.ioctl_reqs[0]);
  EXPECT_EQ("br", system.ioctl_ifreq_args[0].first);
}

TEST(DatapathTest, RemoveBridge) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_ip(*runner, "link set br down");

  Datapath datapath(runner, firewall, &system);
  datapath.RemoveBridge("br");

  EXPECT_EQ(1, system.ioctl_reqs.size());
  EXPECT_EQ(SIOCBRDELBR, system.ioctl_reqs[0]);
  EXPECT_EQ("br", system.ioctl_ifreq_args[0].first);
}

TEST(DatapathTest, AddToBridge) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  EXPECT_CALL(system, IfNametoindex("vethwlan0")).WillRepeatedly(Return(5));

  Datapath datapath(runner, firewall, &system);
  datapath.AddToBridge("arcbr0", "vethwlan0");

  EXPECT_EQ(1, system.ioctl_reqs.size());
  EXPECT_EQ(SIOCBRADDIF, system.ioctl_reqs[0]);
  EXPECT_EQ("arcbr0", system.ioctl_ifreq_args[0].first);
  EXPECT_EQ(5, system.ioctl_ifreq_args[0].second.ifr_ifindex);
}

TEST(DatapathTest, ConnectVethPair) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip(*runner,
            "link add veth_foo type veth peer name peer_foo netns netns_foo");
  Verify_ip(*runner,
            "addr add 100.115.92.169/30 brd 100.115.92.171 dev peer_foo");
  Verify_ip(*runner,
            "link set dev peer_foo up addr 01:02:03:04:05:06 multicast on");
  Verify_ip(*runner, "link set veth_foo up");
  Datapath datapath(runner, firewall, &system);
  EXPECT_TRUE(datapath.ConnectVethPair(kTestPID, "netns_foo", "veth_foo",
                                       "peer_foo", {1, 2, 3, 4, 5, 6},
                                       Ipv4Addr(100, 115, 92, 169), 30, true));
}

TEST(DatapathTest, AddVirtualInterfacePair) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip(*runner,
            "link add veth_foo type veth peer name peer_foo netns netns_foo");
  Datapath datapath(runner, firewall, &system);
  EXPECT_TRUE(
      datapath.AddVirtualInterfacePair("netns_foo", "veth_foo", "peer_foo"));
}

TEST(DatapathTest, ToggleInterface) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip(*runner, "link set foo up");
  Verify_ip(*runner, "link set bar down");
  Datapath datapath(runner, firewall, &system);
  EXPECT_TRUE(datapath.ToggleInterface("foo", true));
  EXPECT_TRUE(datapath.ToggleInterface("bar", false));
}

TEST(DatapathTest, ConfigureInterface) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip(*runner, "addr add 1.1.1.1/30 brd 1.1.1.3 dev foo");
  Verify_ip(*runner, "link set dev foo up addr 02:02:02:02:02:02 multicast on");

  Datapath datapath(runner, firewall, &system);
  MacAddress mac_addr = {2, 2, 2, 2, 2, 2};
  EXPECT_TRUE(datapath.ConfigureInterface("foo", mac_addr, Ipv4Addr(1, 1, 1, 1),
                                          30, true, true));
}

TEST(DatapathTest, RemoveInterface) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip(*runner, "link delete foo");
  Datapath datapath(runner, firewall, &system);
  datapath.RemoveInterface("foo");
}

TEST(DatapathTest, StartRoutingNamespace) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  MacAddress peer_mac = {1, 2, 3, 4, 5, 6};
  MacAddress host_mac = {6, 5, 4, 3, 2, 1};

  Verify_ip_netns_delete(*runner, "netns_foo");
  Verify_ip_netns_attach(*runner, "netns_foo", kTestPID);
  Verify_ip(*runner,
            "link add arc_ns0 type veth peer name veth0 netns netns_foo");
  Verify_ip(*runner, "addr add 100.115.92.130/30 brd 100.115.92.131 dev veth0");
  Verify_ip(*runner,
            "link set dev veth0 up addr 01:02:03:04:05:06 multicast off");
  Verify_ip(*runner, "link set arc_ns0 up");
  Verify_ip(*runner,
            "addr add 100.115.92.129/30 brd 100.115.92.131 dev arc_ns0");
  Verify_ip(*runner,
            "link set dev arc_ns0 up addr 06:05:04:03:02:01 multicast off");
  Verify_iptables(*runner, Dual, "filter -A FORWARD -o arc_ns0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -A FORWARD -i arc_ns0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "mangle -N PREROUTING_arc_ns0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_arc_ns0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i arc_ns0 -j PREROUTING_arc_ns0 -w");
  Verify_iptables(*runner, IPv4,
                  "mangle -A PREROUTING_arc_ns0 -j MARK --set-mark "
                  "0x00000001/0x00000001 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arc_ns0 -j MARK --set-mark "
                  "0x00000200/0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arc_ns0 -j CONNMARK "
                  "--restore-mark --mask 0xffff0000 -w");
  Verify_iptables(*runner, IPv4,
                  "mangle -A PREROUTING_arc_ns0 -s 100.115.92.130 -d "
                  "100.115.92.129 -j ACCEPT -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arc_ns0 -j apply_vpn_mark -w");

  ConnectedNamespace nsinfo = {};
  nsinfo.pid = kTestPID;
  nsinfo.netns_name = "netns_foo";
  nsinfo.source = TrafficSource::USER;
  nsinfo.outbound_ifname = "";
  nsinfo.route_on_vpn = true;
  nsinfo.host_ifname = "arc_ns0";
  nsinfo.peer_ifname = "veth0";
  nsinfo.peer_subnet = std::make_unique<Subnet>(Ipv4Addr(100, 115, 92, 128), 30,
                                                base::DoNothing());
  nsinfo.peer_mac_addr = peer_mac;
  nsinfo.host_mac_addr = host_mac;
  Datapath datapath(runner, firewall, &system);
  datapath.StartRoutingNamespace(nsinfo);
}

TEST(DatapathTest, StopRoutingNamespace) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, Dual, "filter -D FORWARD -o arc_ns0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -D FORWARD -i arc_ns0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i arc_ns0 -j PREROUTING_arc_ns0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_arc_ns0 -w");
  Verify_iptables(*runner, Dual, "mangle -X PREROUTING_arc_ns0 -w");
  Verify_ip_netns_delete(*runner, "netns_foo");
  Verify_ip(*runner, "link delete arc_ns0");

  ConnectedNamespace nsinfo = {};
  nsinfo.pid = kTestPID;
  nsinfo.netns_name = "netns_foo";
  nsinfo.source = TrafficSource::USER;
  nsinfo.outbound_ifname = "";
  nsinfo.route_on_vpn = true;
  nsinfo.host_ifname = "arc_ns0";
  nsinfo.peer_ifname = "veth0";
  nsinfo.peer_subnet = std::make_unique<Subnet>(Ipv4Addr(100, 115, 92, 128), 30,
                                                base::DoNothing());
  Datapath datapath(runner, firewall, &system);
  datapath.StopRoutingNamespace(nsinfo);
}

TEST(DatapathTest, StartRoutingNewNamespace) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  MacAddress mac = {1, 2, 3, 4, 5, 6};

  // The running may fail at checking ScopedNS.IsValid() in
  // Datapath::ConnectVethPair(), so we only check if `ip netns add` is invoked
  // correctly here.
  Verify_ip_netns_add(*runner, "netns_foo");

  ConnectedNamespace nsinfo = {};
  nsinfo.pid = ConnectedNamespace::kNewNetnsPid;
  nsinfo.netns_name = "netns_foo";
  nsinfo.source = TrafficSource::USER;
  nsinfo.outbound_ifname = "";
  nsinfo.route_on_vpn = true;
  nsinfo.host_ifname = "arc_ns0";
  nsinfo.peer_ifname = "veth0";
  nsinfo.peer_subnet = std::make_unique<Subnet>(Ipv4Addr(100, 115, 92, 128), 30,
                                                base::DoNothing());
  nsinfo.peer_mac_addr = mac;
  Datapath datapath(runner, firewall, &system);
  datapath.StartRoutingNamespace(nsinfo);
}

TEST(DatapathTest, StartRoutingDevice_Arc) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  EXPECT_CALL(system, IfNametoindex("eth0")).WillRepeatedly(Return(2));
  Verify_iptables(*runner, Dual, "filter -A FORWARD -o arc_eth0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -A FORWARD -i arc_eth0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "mangle -N PREROUTING_arc_eth0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_arc_eth0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i arc_eth0 -j PREROUTING_arc_eth0 -w");
  Verify_iptables(*runner, IPv4,
                  "mangle -A PREROUTING_arc_eth0 -j MARK --set-mark "
                  "0x00000001/0x00000001 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arc_eth0 -j MARK --set-mark "
                  "0x00002000/0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arc_eth0 -j MARK --set-mark "
                  "0x03ea0000/0xffff0000 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StartRoutingDevice("eth0", "arc_eth0", Ipv4Addr(1, 2, 3, 4),
                              TrafficSource::ARC, false);
}

TEST(DatapathTest, StartRoutingDevice_CrosVM) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_iptables(*runner, Dual, "filter -A FORWARD -o vmtap0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -A FORWARD -i vmtap0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "mangle -N PREROUTING_vmtap0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_vmtap0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i vmtap0 -j PREROUTING_vmtap0 -w");
  Verify_iptables(*runner, IPv4,
                  "mangle -A PREROUTING_vmtap0 -j MARK --set-mark "
                  "0x00000001/0x00000001 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_vmtap0 -j MARK --set-mark "
                  "0x00002100/0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_vmtap0 -j CONNMARK --restore-mark "
                  "--mask 0xffff0000 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_vmtap0 -j skip_apply_vpn_mark -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_vmtap0 -j apply_vpn_mark -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StartRoutingDevice("", "vmtap0", Ipv4Addr(1, 2, 3, 4),
                              TrafficSource::CROSVM, true);
}

TEST(DatapathTest, StopRoutingDevice_Arc) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_iptables(*runner, Dual, "filter -D FORWARD -o arc_eth0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -D FORWARD -i arc_eth0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i arc_eth0 -j PREROUTING_arc_eth0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_arc_eth0 -w");
  Verify_iptables(*runner, Dual, "mangle -X PREROUTING_arc_eth0 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StopRoutingDevice("eth0", "arc_eth0", Ipv4Addr(1, 2, 3, 4),
                             TrafficSource::ARC, true);
}

TEST(DatapathTest, StopRoutingDevice_CrosVM) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_iptables(*runner, Dual, "filter -D FORWARD -o vmtap0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -D FORWARD -i vmtap0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i vmtap0 -j PREROUTING_vmtap0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_vmtap0 -w");
  Verify_iptables(*runner, Dual, "mangle -X PREROUTING_vmtap0 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StopRoutingDevice("", "vmtap0", Ipv4Addr(1, 2, 3, 4),
                             TrafficSource::CROSVM, true);
}

TEST(DatapathTest, StartStopConnectionPinning) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  // Setup
  EXPECT_CALL(system, IfNametoindex("eth0")).WillRepeatedly(Return(3));
  Verify_iptables(*runner, Dual, "mangle -N POSTROUTING_eth0 -w");
  Verify_iptables(*runner, Dual, "mangle -F POSTROUTING_eth0 -w",
                  2 /* Start and Stop */);
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING -o eth0 -j POSTROUTING_eth0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING_eth0 -j CONNMARK --set-mark "
                  "0x03eb0000/0xffff0000 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING_eth0 -j CONNMARK "
                  "--save-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i eth0 -j CONNMARK "
                  "--restore-mark --mask 0x00003f00 -w");

  // Teardown
  Verify_iptables(*runner, Dual,
                  "mangle -D POSTROUTING -o eth0 -j POSTROUTING_eth0 -w");
  Verify_iptables(*runner, Dual, "mangle -X POSTROUTING_eth0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i eth0 -j CONNMARK "
                  "--restore-mark --mask 0x00003f00 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StartConnectionPinning("eth0");
  datapath.StopConnectionPinning("eth0");
}

TEST(DatapathTest, StartStopVpnRouting_ArcVpn) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  // Setup
  EXPECT_CALL(system, IfNametoindex("arcbr0")).WillRepeatedly(Return(5));
  Verify_iptables(*runner, Dual, "mangle -N POSTROUTING_arcbr0 -w");
  Verify_iptables(*runner, Dual, "mangle -F POSTROUTING_arcbr0 -w",
                  2 /* Start and Stop */);
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING -o arcbr0 -j POSTROUTING_arcbr0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING_arcbr0 -j CONNMARK "
                  "--set-mark 0x03ed0000/0xffff0000 -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -A apply_vpn_mark -m mark ! --mark 0x0/0xffff0000 -j ACCEPT -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -A apply_vpn_mark -j MARK --set-mark 0x03ed0000/0xffff0000 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING_arcbr0 -j CONNMARK "
                  "--save-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i arcbr0 -j CONNMARK "
                  "--restore-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A POSTROUTING -o arcbr0 -j MASQUERADE -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A OUTPUT -m mark ! --mark 0x00008000/0x0000c000 -j "
                  "redirect_dns -w");
  Verify_iptables(*runner, Dual,
                  "filter -A vpn_accept -m mark "
                  "--mark 0x03ed0000/0xffff0000 -j ACCEPT -w");

  // Teardown
  Verify_iptables(*runner, Dual,
                  "mangle -D POSTROUTING -o arcbr0 -j POSTROUTING_arcbr0 -w");
  Verify_iptables(*runner, Dual, "mangle -X POSTROUTING_arcbr0 -w");
  Verify_iptables(*runner, Dual, "mangle -F apply_vpn_mark -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i arcbr0 -j CONNMARK "
                  "--restore-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D POSTROUTING -o arcbr0 -j MASQUERADE -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D OUTPUT -m mark ! --mark 0x00008000/0x0000c000 -j "
                  "redirect_dns -w");
  Verify_iptables(*runner, Dual, "filter -F vpn_accept -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StartVpnRouting("arcbr0");
  datapath.StopVpnRouting("arcbr0");
}

TEST(DatapathTest, StartStopVpnRouting_HostVpn) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  // Setup
  EXPECT_CALL(system, IfNametoindex("tun0")).WillRepeatedly(Return(5));
  Verify_iptables(*runner, Dual, "mangle -N POSTROUTING_tun0 -w");
  Verify_iptables(*runner, Dual, "mangle -F POSTROUTING_tun0 -w",
                  2 /* Start and Stop */);
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING -o tun0 -j POSTROUTING_tun0 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING_tun0 -j CONNMARK --set-mark "
                  "0x03ed0000/0xffff0000 -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -A apply_vpn_mark -m mark ! --mark 0x0/0xffff0000 -j ACCEPT -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -A apply_vpn_mark -j MARK --set-mark 0x03ed0000/0xffff0000 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A POSTROUTING_tun0 -j CONNMARK "
                  "--save-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i tun0 -j CONNMARK "
                  "--restore-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, IPv4, "nat -A POSTROUTING -o tun0 -j MASQUERADE -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A OUTPUT -m mark ! --mark 0x00008000/0x0000c000 -j "
                  "redirect_dns -w");
  Verify_iptables(*runner, Dual,
                  "filter -A vpn_accept -m mark "
                  "--mark 0x03ed0000/0xffff0000 -j ACCEPT -w");
  // Teardown
  Verify_iptables(*runner, Dual,
                  "mangle -D POSTROUTING -o tun0 -j POSTROUTING_tun0 -w");
  Verify_iptables(*runner, Dual, "mangle -X POSTROUTING_tun0 -w");
  Verify_iptables(*runner, Dual, "mangle -F apply_vpn_mark -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i tun0 -j CONNMARK "
                  "--restore-mark --mask 0x00003f00 -w");
  Verify_iptables(*runner, IPv4, "nat -D POSTROUTING -o tun0 -j MASQUERADE -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D OUTPUT -m mark ! --mark 0x00008000/0x0000c000 -j "
                  "redirect_dns -w");
  Verify_iptables(*runner, Dual, "filter -F vpn_accept -w");
  // Start arcbr0 routing
  Verify_iptables(*runner, Dual, "filter -A FORWARD -o arcbr0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -A FORWARD -i arcbr0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "mangle -N PREROUTING_arcbr0 -w");
  Verify_iptables(*runner, Dual, "mangle -F PREROUTING_arcbr0 -w",
                  2 /* Start and Stop */);
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING -i arcbr0 -j PREROUTING_arcbr0 -w");
  Verify_iptables(*runner, IPv4,
                  "mangle -A PREROUTING_arcbr0 -j MARK --set-mark "
                  "0x00000001/0x00000001 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arcbr0 -j MARK --set-mark "
                  "0x00002000/0x00003f00 -w");
  Verify_iptables(*runner, Dual,
                  "mangle -A PREROUTING_arcbr0 -j MARK --set-mark "
                  "0x03ed0000/0xffff0000 -w");
  // Stop arcbr0 routing
  Verify_iptables(*runner, Dual, "filter -D FORWARD -o arcbr0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual, "filter -D FORWARD -i arcbr0 -j ACCEPT -w");
  Verify_iptables(*runner, Dual,
                  "mangle -D PREROUTING -i arcbr0 -j PREROUTING_arcbr0 -w");
  Verify_iptables(*runner, Dual, "mangle -X PREROUTING_arcbr0 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.StartVpnRouting("tun0");
  datapath.StopVpnRouting("tun0");
}

TEST(DatapathTest, AddInboundIPv4DNAT) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_iptables(*runner, IPv4,
                  "nat -A ingress_default_forwarding -i eth0 -m socket "
                  "--nowildcard -j ACCEPT -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A ingress_default_forwarding -i eth0 -p tcp -j DNAT "
                  "--to-destination 1.2.3.4 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A ingress_default_forwarding -i eth0 -p udp -j DNAT "
                  "--to-destination 1.2.3.4 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.AddInboundIPv4DNAT("eth0", "1.2.3.4");
}

TEST(DatapathTest, RemoveInboundIPv4DNAT) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_iptables(*runner, IPv4,
                  "nat -D ingress_default_forwarding -i eth0 -m socket "
                  "--nowildcard -j ACCEPT -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D ingress_default_forwarding -i eth0 -p tcp -j DNAT "
                  "--to-destination 1.2.3.4 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D ingress_default_forwarding -i eth0 -p udp -j DNAT "
                  "--to-destination 1.2.3.4 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.RemoveInboundIPv4DNAT("eth0", "1.2.3.4");
}

TEST(DatapathTest, MaskInterfaceFlags) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Datapath datapath(runner, firewall, &system);
  bool result = datapath.MaskInterfaceFlags("foo0", IFF_DEBUG);

  EXPECT_TRUE(result);
  std::vector<ioctl_req_t> expected = {SIOCGIFFLAGS, SIOCSIFFLAGS};
  EXPECT_EQ(system.ioctl_reqs, expected);
}

TEST(DatapathTest, AddIPv6HostRoute) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;
  Verify_ip6(*runner, "route replace 2001:da8:e00::1234/128 dev eth0");
  Datapath datapath(runner, firewall, &system);
  datapath.AddIPv6HostRoute("eth0", "2001:da8:e00::1234", 128);
}

TEST(DatapathTest, AddIPv4Route) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Datapath datapath(runner, firewall, &system);

  datapath.AddIPv4Route(Ipv4Addr(192, 168, 1, 1), Ipv4Addr(100, 115, 93, 0),
                        Ipv4Addr(255, 255, 255, 0));
  datapath.DeleteIPv4Route(Ipv4Addr(192, 168, 1, 1), Ipv4Addr(100, 115, 93, 0),
                           Ipv4Addr(255, 255, 255, 0));
  datapath.AddIPv4Route("eth0", Ipv4Addr(100, 115, 92, 8),
                        Ipv4Addr(255, 255, 255, 252));
  datapath.DeleteIPv4Route("eth0", Ipv4Addr(100, 115, 92, 8),
                           Ipv4Addr(255, 255, 255, 252));

  std::vector<ioctl_req_t> expected_reqs = {SIOCADDRT, SIOCDELRT, SIOCADDRT,
                                            SIOCDELRT};
  EXPECT_EQ(expected_reqs, system.ioctl_reqs);

  std::string route1 =
      "{rt_dst: {family: AF_INET, port: 0, addr: 100.115.93.0}, rt_genmask: "
      "{family: AF_INET, port: 0, addr: 255.255.255.0}, rt_gateway: {family: "
      "AF_INET, port: 0, addr: 192.168.1.1}, rt_dev: null, rt_flags: RTF_UP | "
      "RTF_GATEWAY}";
  std::string route2 =
      "{rt_dst: {family: AF_INET, port: 0, addr: 100.115.92.8}, rt_genmask: "
      "{family: AF_INET, port: 0, addr: 255.255.255.252}, rt_gateway: {unset}, "
      "rt_dev: eth0, rt_flags: RTF_UP | RTF_GATEWAY}";
  std::vector<std::string> captured_routes;
  for (const auto& route : system.ioctl_rtentry_args) {
    std::ostringstream stream;
    stream << route.second;
    captured_routes.emplace_back(stream.str());
  }
  EXPECT_EQ(route1, captured_routes[0]);
  EXPECT_EQ(route1, captured_routes[1]);
  EXPECT_EQ(route2, captured_routes[2]);
  EXPECT_EQ(route2, captured_routes[3]);
}

TEST(DatapathTest, RedirectDnsRules) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_dns -p tcp --dport 53 -o eth0 -j DNAT "
                  "--to-destination 192.168.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_dns -p udp --dport 53 -o eth0 -j DNAT "
                  "--to-destination 192.168.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_dns -p tcp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 1.1.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_dns -p udp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 1.1.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_dns -p tcp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 1.1.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_dns -p udp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 1.1.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_dns -p tcp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 8.8.8.8 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_dns -p udp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 8.8.8.8 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_dns -p tcp --dport 53 -o eth0 -j DNAT "
                  "--to-destination 192.168.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_dns -p udp --dport 53 -o eth0 -j DNAT "
                  "--to-destination 192.168.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_dns -p tcp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 8.8.8.8 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_dns -p udp --dport 53 -o wlan0 -j DNAT "
                  "--to-destination 8.8.8.8 -w");

  Datapath datapath(runner, firewall, &system);
  datapath.RemoveRedirectDnsRule("wlan0");
  datapath.RemoveRedirectDnsRule("unknown");
  datapath.AddRedirectDnsRule("eth0", "192.168.1.1");
  datapath.AddRedirectDnsRule("wlan0", "1.1.1.1");
  datapath.AddRedirectDnsRule("wlan0", "8.8.8.8");
  datapath.RemoveRedirectDnsRule("eth0");
  datapath.RemoveRedirectDnsRule("wlan0");
}

TEST(DatapathTest, DumpIptables) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  EXPECT_CALL(*runner,
              iptables(StrEq("mangle"),
                       ElementsAre("-L", "-x", "-v", "-n", "-w"), _, _))
      .WillOnce(DoAll(SetArgPointee<3>("<iptables output>"), Return(0)));
  EXPECT_CALL(*runner,
              ip6tables(StrEq("mangle"),
                        ElementsAre("-L", "-x", "-v", "-n", "-w"), _, _))
      .WillOnce(DoAll(SetArgPointee<3>("<ip6tables output>"), Return(0)));

  Datapath datapath(runner, firewall, &system);
  EXPECT_EQ("<iptables output>",
            datapath.DumpIptables(IpFamily::IPv4, "mangle"));
  EXPECT_EQ("<ip6tables output>",
            datapath.DumpIptables(IpFamily::IPv6, "mangle"));
  EXPECT_EQ("", datapath.DumpIptables(IpFamily::Dual, "mangle"));
}

TEST(DatapathTest, SetVpnLockdown) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, Dual,
                  "filter -A vpn_lockdown -m mark --mark 0x00008000/0x0000c000 "
                  "-j REJECT -w");
  Verify_iptables(*runner, Dual, "filter -F vpn_lockdown -w");

  Datapath datapath(runner, firewall, &system);
  datapath.SetVpnLockdown(true);
  datapath.SetVpnLockdown(false);
}

TEST(DatapathTest, ArcVethHostName) {
  EXPECT_EQ("vetheth0", ArcVethHostName("eth0"));
  EXPECT_EQ("vethrmnet0", ArcVethHostName("rmnet0"));
  EXPECT_EQ("vethrmnet_data0", ArcVethHostName("rmnet_data0"));
  EXPECT_EQ("vethifnamsiz_i0", ArcVethHostName("ifnamsiz_ifnam0"));
  auto ifname = ArcVethHostName("exceeds_ifnamesiz_checkanyway");
  EXPECT_EQ("vethexceeds_ify", ifname);
  EXPECT_LT(ifname.length(), IFNAMSIZ);
}

TEST(DatapathTest, ArcBridgeName) {
  EXPECT_EQ("arc_eth0", ArcBridgeName("eth0"));
  EXPECT_EQ("arc_rmnet0", ArcBridgeName("rmnet0"));
  EXPECT_EQ("arc_rmnet_data0", ArcBridgeName("rmnet_data0"));
  EXPECT_EQ("arc_ifnamsiz_i0", ArcBridgeName("ifnamsiz_ifnam0"));
  auto ifname = ArcBridgeName("exceeds_ifnamesiz_checkanyway");
  EXPECT_EQ("arc_exceeds_ify", ifname);
  EXPECT_LT(ifname.length(), IFNAMSIZ);
}

TEST(DatapathTest, SetConntrackHelpers) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  EXPECT_CALL(system, SysNetSet(System::SysNet::ConntrackHelper, "1", ""));
  EXPECT_CALL(system, SysNetSet(System::SysNet::ConntrackHelper, "0", ""));

  Datapath datapath(runner, firewall, &system);
  datapath.SetConntrackHelpers(true);
  datapath.SetConntrackHelpers(false);
}

TEST(DatapathTest, StartDnsRedirection_Default) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_default_dns -i vmtap0 -p udp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_default_dns -i vmtap0 -p tcp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -I redirect_default_dns -i vmtap0 -p udp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -I redirect_default_dns -i vmtap0 -p tcp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");

  DnsRedirectionRule rule4 = {};
  rule4.type = patchpanel::SetDnsRedirectionRuleRequest::DEFAULT;
  rule4.input_ifname = "vmtap0";
  rule4.proxy_address = "100.115.92.130";
  DnsRedirectionRule rule6 = {};
  rule6.type = patchpanel::SetDnsRedirectionRuleRequest::DEFAULT;
  rule6.input_ifname = "vmtap0";
  rule6.proxy_address = "::1";

  Datapath datapath(runner, firewall, &system);
  datapath.StartDnsRedirection(rule4);
  datapath.StartDnsRedirection(rule6);
}

TEST(DatapathTest, StartDnsRedirection_Arc) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_arc_dns -i arc_eth0 -p udp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -I redirect_arc_dns -i arc_eth0 -p tcp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -I redirect_arc_dns -i arc_eth0 -p udp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -I redirect_arc_dns -i arc_eth0 -p tcp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");

  DnsRedirectionRule rule4 = {};
  rule4.type = patchpanel::SetDnsRedirectionRuleRequest::ARC;
  rule4.input_ifname = "arc_eth0";
  rule4.proxy_address = "100.115.92.130";
  DnsRedirectionRule rule6 = {};
  rule6.type = patchpanel::SetDnsRedirectionRuleRequest::ARC;
  rule6.input_ifname = "arc_eth0";
  rule6.proxy_address = "::1";

  Datapath datapath(runner, firewall, &system);
  datapath.StartDnsRedirection(rule4);
  datapath.StartDnsRedirection(rule6);
}

TEST(DatapathTest, StartDnsRedirection_User) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(
      *runner, IPv4,
      "nat -I redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 8.8.8.8 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -I redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 8.4.8.4 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -I redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 3 --packet "
      "0 -j DNAT --to-destination 1.1.1.1 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -I redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 8.8.8.8 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -I redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 8.4.8.4 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -I redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 3 --packet "
      "0 -j DNAT --to-destination 1.1.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A redirect_user_dns -p udp --dport 53 -j DNAT "
                  "--to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -A redirect_user_dns -p tcp --dport 53 -j DNAT "
                  "--to-destination 100.115.92.130 -w");

  Verify_iptables(
      *runner, IPv6,
      "nat -I redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8888 -w");
  Verify_iptables(
      *runner, IPv6,
      "nat -I redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8844 -w");
  Verify_iptables(
      *runner, IPv6,
      "nat -I redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8888 -w");
  Verify_iptables(
      *runner, IPv6,
      "nat -I redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8844 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -A snat_user_dns -p udp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(*runner, IPv6,
                  "nat -A snat_user_dns -p tcp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(*runner, IPv6,
                  "nat -A redirect_user_dns -p udp --dport 53 -j DNAT "
                  "--to-destination ::1 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -A redirect_user_dns -p tcp --dport 53 -j DNAT "
                  "--to-destination ::1 -w");

  Verify_iptables(*runner, Dual,
                  "nat -I snat_chrome_dns -p udp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(*runner, Dual,
                  "nat -I snat_chrome_dns -p tcp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -A skip_apply_vpn_mark -p udp --dport 53 -j ACCEPT -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -A skip_apply_vpn_mark -p tcp --dport 53 -j ACCEPT -w");

  DnsRedirectionRule rule4 = {};
  rule4.type = patchpanel::SetDnsRedirectionRuleRequest::USER;
  rule4.input_ifname = "";
  rule4.proxy_address = "100.115.92.130";
  rule4.nameservers.emplace_back("8.8.8.8");
  rule4.nameservers.emplace_back("8.4.8.4");
  rule4.nameservers.emplace_back("1.1.1.1");
  DnsRedirectionRule rule6 = {};
  rule6.type = patchpanel::SetDnsRedirectionRuleRequest::USER;
  rule6.input_ifname = "";
  rule6.proxy_address = "::1";
  rule6.nameservers.emplace_back("2001:4860:4860::8888");
  rule6.nameservers.emplace_back("2001:4860:4860::8844");

  Datapath datapath(runner, firewall, &system);
  datapath.StartDnsRedirection(rule4);
  datapath.StartDnsRedirection(rule6);
}

TEST(DatapathTest, StopDnsRedirection_Default) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_default_dns -i vmtap0 -p udp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_default_dns -i vmtap0 -p tcp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D redirect_default_dns -i vmtap0 -p udp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D redirect_default_dns -i vmtap0 -p tcp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");

  DnsRedirectionRule rule4 = {};
  rule4.type = patchpanel::SetDnsRedirectionRuleRequest::DEFAULT;
  rule4.input_ifname = "vmtap0";
  rule4.proxy_address = "100.115.92.130";
  DnsRedirectionRule rule6 = {};
  rule6.type = patchpanel::SetDnsRedirectionRuleRequest::DEFAULT;
  rule6.input_ifname = "vmtap0";
  rule6.proxy_address = "::1";

  Datapath datapath(runner, firewall, &system);
  datapath.StopDnsRedirection(rule4);
  datapath.StopDnsRedirection(rule6);
}

TEST(DatapathTest, StopDnsRedirection_Arc) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_arc_dns -i arc_eth0 -p udp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_arc_dns -i arc_eth0 -p tcp --dport 53 -j "
                  "DNAT --to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D redirect_arc_dns -i arc_eth0 -p udp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D redirect_arc_dns -i arc_eth0 -p tcp --dport 53 -j "
                  "DNAT --to-destination ::1 -w");

  DnsRedirectionRule rule4 = {};
  rule4.type = patchpanel::SetDnsRedirectionRuleRequest::ARC;
  rule4.input_ifname = "arc_eth0";
  rule4.proxy_address = "100.115.92.130";
  DnsRedirectionRule rule6 = {};
  rule6.type = patchpanel::SetDnsRedirectionRuleRequest::ARC;
  rule6.input_ifname = "arc_eth0";
  rule6.proxy_address = "::1";

  Datapath datapath(runner, firewall, &system);
  datapath.StopDnsRedirection(rule4);
  datapath.StopDnsRedirection(rule6);
}

TEST(DatapathTest, StopDnsRedirection_User) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Verify_iptables(
      *runner, IPv4,
      "nat -D redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 8.8.8.8 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -D redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 8.4.8.4 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -D redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 3 --packet "
      "0 -j DNAT --to-destination 1.1.1.1 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -D redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 8.8.8.8 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -D redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 8.4.8.4 -w");
  Verify_iptables(
      *runner, IPv4,
      "nat -D redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 3 --packet "
      "0 -j DNAT --to-destination 1.1.1.1 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_user_dns -p udp --dport 53 -j DNAT "
                  "--to-destination 100.115.92.130 -w");
  Verify_iptables(*runner, IPv4,
                  "nat -D redirect_user_dns -p tcp --dport 53 -j DNAT "
                  "--to-destination 100.115.92.130 -w");

  Verify_iptables(
      *runner, IPv6,
      "nat -D redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8888 -w");
  Verify_iptables(
      *runner, IPv6,
      "nat -D redirect_chrome_dns -p udp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8844 -w");
  Verify_iptables(
      *runner, IPv6,
      "nat -D redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 1 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8888 -w");
  Verify_iptables(
      *runner, IPv6,
      "nat -D redirect_chrome_dns -p tcp --dport 53 -m owner "
      "--uid-owner chronos -m statistic --mode nth --every 2 --packet "
      "0 -j DNAT --to-destination 2001:4860:4860::8844 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D snat_user_dns -p udp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D snat_user_dns -p tcp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D redirect_user_dns -p udp --dport 53 -j DNAT "
                  "--to-destination ::1 -w");
  Verify_iptables(*runner, IPv6,
                  "nat -D redirect_user_dns -p tcp --dport 53 -j DNAT "
                  "--to-destination ::1 -w");

  Verify_iptables(*runner, Dual,
                  "nat -D snat_chrome_dns -p udp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(*runner, Dual,
                  "nat -D snat_chrome_dns -p tcp --dport 53 -j "
                  "MASQUERADE -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -D skip_apply_vpn_mark -p udp --dport 53 -j ACCEPT -w");
  Verify_iptables(
      *runner, Dual,
      "mangle -D skip_apply_vpn_mark -p tcp --dport 53 -j ACCEPT -w");

  DnsRedirectionRule rule4 = {};
  rule4.type = patchpanel::SetDnsRedirectionRuleRequest::USER;
  rule4.input_ifname = "";
  rule4.proxy_address = "100.115.92.130";
  rule4.nameservers.emplace_back("8.8.8.8");
  rule4.nameservers.emplace_back("8.4.8.4");
  rule4.nameservers.emplace_back("1.1.1.1");
  DnsRedirectionRule rule6 = {};
  rule6.type = patchpanel::SetDnsRedirectionRuleRequest::USER;
  rule6.input_ifname = "";
  rule6.proxy_address = "::1";
  rule6.nameservers.emplace_back("2001:4860:4860::8888");
  rule6.nameservers.emplace_back("2001:4860:4860::8844");

  Datapath datapath(runner, firewall, &system);
  datapath.StopDnsRedirection(rule4);
  datapath.StopDnsRedirection(rule6);
}

TEST(DatapathTest, SetRouteLocalnet) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  EXPECT_CALL(system,
              SysNetSet(System::SysNet::IPv4RouteLocalnet, "1", "eth0"));
  EXPECT_CALL(system,
              SysNetSet(System::SysNet::IPv4RouteLocalnet, "0", "wlan0"));

  Datapath datapath(runner, firewall, &system);
  datapath.SetRouteLocalnet("eth0", true);
  datapath.SetRouteLocalnet("wlan0", false);
}

TEST(DatapathTest, ModprobeAll) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  EXPECT_CALL(*runner, modprobe_all(ElementsAre("ip6table_filter", "ah6",
                                                "esp6", "nf_nat_ftp"),
                                    _));

  Datapath datapath(runner, firewall, &system);
  datapath.ModprobeAll({"ip6table_filter", "ah6", "esp6", "nf_nat_ftp"});
}

TEST(DatapathTest, ModifyPortRule) {
  auto runner = new MockProcessRunner();
  auto firewall = new MockFirewall();
  FakeSystem system;

  Datapath datapath(runner, firewall, &system);
  patchpanel::ModifyPortRuleRequest request;
  request.set_input_ifname("eth0");
  request.set_input_dst_ip("192.168.1.1");
  request.set_input_dst_port(80);
  request.set_dst_ip("100.115.92.14");
  request.set_dst_port(8080);

  // Invalid request #1
  request.set_op(patchpanel::ModifyPortRuleRequest::INVALID_OPERATION);
  request.set_proto(patchpanel::ModifyPortRuleRequest::TCP);
  request.set_type(patchpanel::ModifyPortRuleRequest::ACCESS);
  EXPECT_CALL(*firewall, AddAcceptRules(_, _, _)).Times(0);
  EXPECT_FALSE(datapath.ModifyPortRule(request));
  Mock::VerifyAndClearExpectations(firewall);

  // Invalid request #2
  request.set_op(patchpanel::ModifyPortRuleRequest::CREATE);
  request.set_proto(patchpanel::ModifyPortRuleRequest::INVALID_PROTOCOL);
  request.set_type(patchpanel::ModifyPortRuleRequest::ACCESS);
  EXPECT_CALL(*firewall, AddAcceptRules(_, _, _)).Times(0);
  EXPECT_FALSE(datapath.ModifyPortRule(request));
  Mock::VerifyAndClearExpectations(firewall);

  // Invalid request #3
  request.set_op(patchpanel::ModifyPortRuleRequest::CREATE);
  request.set_proto(patchpanel::ModifyPortRuleRequest::TCP);
  request.set_type(patchpanel::ModifyPortRuleRequest::INVALID_RULE_TYPE);
  EXPECT_CALL(*firewall, AddAcceptRules(_, _, _)).Times(0);
  EXPECT_FALSE(datapath.ModifyPortRule(request));
  Mock::VerifyAndClearExpectations(firewall);
}

}  // namespace patchpanel
