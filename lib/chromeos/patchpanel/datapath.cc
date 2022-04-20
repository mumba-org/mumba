// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/datapath.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <algorithm>

//#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/userdb_utils.h>

#include "patchpanel/adb_proxy.h"
#include "patchpanel/arc_service.h"

namespace patchpanel {

namespace {
// TODO(hugobenichi) Consolidate this constant definition in a single place.
constexpr pid_t kTestPID = -2;
constexpr char kDefaultIfname[] = "vmtap%d";
constexpr char kTunDev[] = "/dev/net/tun";
constexpr char kArcAddr[] = "100.115.92.2";
constexpr char kLocalhostAddr[] = "127.0.0.1";
constexpr char kDefaultDnsPort[] = "53";
constexpr char kChronosUid[] = "chronos";
constexpr uint16_t kAdbServerPort = 5555;

// Constants used for dropping locally originated traffic bound to an incorrect
// source IPv4 address.
constexpr char kGuestIPv4Subnet[] = "100.115.92.0/23";
constexpr std::array<const char*, 6> kPhysicalIfnamePrefixes{
    {"eth+", "wlan+", "mlan+", "usb+", "wwan+", "rmnet+"}};
constexpr std::array<const char*, 2> kCellularIfnamePrefixes{
    {"wwan+", "rmnet+"}};

// Chains for tagging egress traffic in the OUTPUT and PREROUTING chains of the
// mangle table.
constexpr char kApplyLocalSourceMarkChain[] = "apply_local_source_mark";
constexpr char kSkipApplyVpnMarkChain[] = "skip_apply_vpn_mark";
constexpr char kApplyVpnMarkChain[] = "apply_vpn_mark";

// Egress filter chain for dropping in the OUTPUT chain any local traffic
// incorrectly bound to a static IPv4 address used for ARC or Crostini.
constexpr char kDropGuestIpv4PrefixChain[] = "drop_guest_ipv4_prefix";
// Egress filter chain for preemptively dropping in the FORWARD chain any ARC or
// Crostini traffic that may not be correctly processed in SNAT.
constexpr char kDropGuestInvalidIpv4Chain[] = "drop_guest_invalid_ipv4";

// Egress nat chain for redirecting DNS queries from system services.
// TODO(b/162788331) Remove once dns-proxy has become fully operational.
constexpr char kRedirectDnsChain[] = "redirect_dns";

// VPN egress filter chains for the filter OUTPUT and FORWARD chains.
constexpr char kVpnEgressFiltersChain[] = "vpn_egress_filters";
constexpr char kVpnAcceptChain[] = "vpn_accept";
constexpr char kVpnLockdownChain[] = "vpn_lockdown";

// nat PREROUTING chains for forwarding ingress traffic.
constexpr char kIngressDefaultForwardingChain[] = "ingress_default_forwarding";
// nat PREROUTING chains for egress traffic from downstream guests.
constexpr char kRedirectArcDnsChain[] = "redirect_arc_dns";
constexpr char kRedirectDefaultDnsChain[] = "redirect_default_dns";
// nat OUTPUT chains for egress traffic from processes running on the host.
constexpr char kRedirectChromeDnsChain[] = "redirect_chrome_dns";
constexpr char kRedirectUserDnsChain[] = "redirect_user_dns";
// nat POSTROUTING chains for egress traffic from processes running on the host.
constexpr char kSnatChromeDnsChain[] = "snat_chrome_dns";
constexpr char kSnatUserDnsChain[] = "snat_user_dns";

// Maximum length of an iptables chain name.
constexpr int kIptablesMaxChainLength = 28;

std::string PrefixIfname(const std::string& prefix, const std::string& ifname) {
  std::string n = prefix + ifname;
  if (n.length() < IFNAMSIZ)
    return n;

  // Best effort attempt to preserve the interface number, assuming it's the
  // last char in the name.
  auto c = ifname[ifname.length() - 1];
  n.resize(IFNAMSIZ - 1);
  n[n.length() - 1] = c;
  return n;
}

// ioctl helper that manages the control fd creation and destruction.
bool Ioctl(System* system, ioctl_req_t req, const char* arg) {
  base::ScopedFD control_fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (!control_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create control socket for ioctl request=" << req;
    return false;
  }
  if (system->Ioctl(control_fd.get(), req, arg) != 0) {
    PLOG(ERROR) << "ioctl request=" << req << " failed";
    return false;
  }
  return true;
}

}  // namespace

std::string ArcVethHostName(const std::string& ifname) {
  return PrefixIfname("veth", ifname);
}

std::string ArcBridgeName(const std::string& ifname) {
  return PrefixIfname("arc_", ifname);
}

Datapath::Datapath(System* system)
    : Datapath(new MinijailedProcessRunner(), new Firewall(), system) {}

Datapath::Datapath(MinijailedProcessRunner* process_runner,
                   Firewall* firewall,
                   System* system)
    : system_(system) {
  process_runner_.reset(process_runner);
  firewall_.reset(firewall);
}

void Datapath::Start() {
  // Restart from a clean iptables state in case of an unordered shutdown.
  ResetIptables();

  // Enable IPv4 packet forwarding
  if (!system_->SysNetSet(System::SysNet::IPv4Forward, "1")) {
    LOG(ERROR) << "Failed to update net.ipv4.ip_forward."
               << " Guest connectivity will not work correctly.";
  }

  // Limit local port range: Android owns 47104-61000.
  // TODO(garrick): The original history behind this tweak is gone. Some
  // investigation is needed to see if it is still applicable.
  if (!system_->SysNetSet(System::SysNet::IPLocalPortRange, "32768 47103")) {
    LOG(ERROR) << "Failed to limit local port range. Some Android features or"
               << " apps may not work correctly.";
  }

  // Enable IPv6 packet forwarding
  if (!system_->SysNetSet(System::SysNet::IPv6Forward, "1")) {
    LOG(ERROR) << "Failed to update net.ipv6.conf.all.forwarding."
               << " IPv6 functionality may be broken.";
  }

  // Creates all "stateless" iptables chains used by patchpanel and set up
  // basic jump rules from the builtin chains. All chains that needs to carry
  // some state when patchpanel restarts (for instance: chains for
  // permission_broker rules, traffic accounting chains) are created separately.
  static struct {
    IpFamily family;
    std::string table;
    std::string chain;
  } makeCommands[] = {
      // Set up a mangle chain used in OUTPUT for applying the fwmark
      // TrafficSource tag and tagging the local traffic that should be routed
      // through a VPN.
      {IpFamily::Dual, "mangle", kApplyLocalSourceMarkChain},
      // Set up a mangle chain used in OUTPUT and PREROUTING to skip VPN fwmark
      // tagging applied through "apply_vpn_mark" chain. This is used to protect
      // DNS traffic that should go to the DNS proxy.
      {IpFamily::Dual, "mangle", kSkipApplyVpnMarkChain},
      // Sets up a mangle chain used in OUTPUT and PREROUTING for tagging "user"
      // traffic that should be routed through a VPN.
      {IpFamily::Dual, "mangle", kApplyVpnMarkChain},
      // Set up nat chains for redirecting egress DNS queries to the DNS proxy
      // instances.
      {IpFamily::Dual, "nat", kRedirectArcDnsChain},
      {IpFamily::Dual, "nat", kRedirectDefaultDnsChain},
      {IpFamily::Dual, "nat", kRedirectUserDnsChain},
      {IpFamily::Dual, "nat", kRedirectChromeDnsChain},
      // Set up nat chains for SNAT-ing egress DNS queries to the DNS proxy
      // instances.
      {IpFamily::Dual, "nat", kSnatChromeDnsChain},
      // For the case of non-Chrome "user" DNS queries, there is already an IPv4
      // SNAT rule with the ConnectNamespace. Only IPv6 USER SNAT is needed.
      {IpFamily::IPv6, "nat", kSnatUserDnsChain},
      // b/178331695 Sets up a nat chain used in OUTPUT for redirecting DNS
      // queries of system services. When a VPN is connected, a query routed
      // through a physical network is redirected to the primary nameserver of
      // that network.
      {IpFamily::IPv4, "nat", kRedirectDnsChain},
      // Set up nat chains for redirecting ingress traffic to downstream guests.
      // These chains are only created for IPv4 since downstream guests obtain
      // their own addresses for IPv6.
      {IpFamily::IPv4, "nat", kIngressPortForwardingChain},
      {IpFamily::IPv4, "nat", kIngressDefaultForwardingChain},
      // Create filter subchains for managing the egress firewall VPN rules.
      {IpFamily::Dual, "filter", kVpnEgressFiltersChain},
      {IpFamily::Dual, "filter", kVpnAcceptChain},
      {IpFamily::Dual, "filter", kVpnLockdownChain},
      {IpFamily::IPv4, "filter", kDropGuestIpv4PrefixChain},
      {IpFamily::IPv4, "filter", kDropGuestInvalidIpv4Chain},
      // Create filter subchains for hosting permission_broker firewall rules
      {IpFamily::Dual, "filter", kIngressPortFirewallChain},
      {IpFamily::Dual, "filter", kEgressPortFirewallChain},
  };
  for (const auto& c : makeCommands) {
    if (!AddChain(c.family, c.table, c.chain /*log_failures*/)) {
      LOG(ERROR) << "Failed to create " << c.chain << " chain in " << c.table
                 << " table";
    }
  }

  // Add all static jump commands from builtin chains to chains created by
  // patchpanel.
  static struct {
    IpFamily family;
    std::string table;
    std::string jump_from;
    std::string jump_to;
    std::string op;
  } jumpCommands[] = {
      {IpFamily::Dual, "mangle", "OUTPUT", kApplyLocalSourceMarkChain},
      {IpFamily::Dual, "nat", "PREROUTING", kRedirectArcDnsChain},
      {IpFamily::Dual, "nat", "PREROUTING", kRedirectDefaultDnsChain},
      // "ingress_port_forwarding" must be traversed before
      // "ingress_default_forwarding".
      {IpFamily::IPv4, "nat", "PREROUTING", kIngressPortForwardingChain},
      {IpFamily::IPv4, "nat", "PREROUTING", kIngressDefaultForwardingChain},
      // When VPN lockdown is enabled, a REJECT rule must stop
      // any egress traffic tagged with the |kFwmarkRouteOnVpn| intent mark.
      // This REJECT rule is added to |kVpnLockdownChain|. In addition, when VPN
      // lockdown is enabled and a VPN is connected, an ACCEPT rule protects the
      // traffic tagged with the VPN routing mark from being reject by the VPN
      // lockdown rule. This ACCEPT rule is added to |kVpnAcceptChain|.
      // Therefore, egress traffic must:
      //   - traverse kVpnAcceptChain before kVpnLockdownChain,
      //   - traverse kVpnLockdownChain before other ACCEPT rules in OUTPUT and
      //   FORWARD.
      // Finally, egress VPN filter rules must be inserted in front of the
      // OUTPUT chain to override basic rules set outside patchpanel.
      {IpFamily::Dual, "filter", "OUTPUT", kVpnEgressFiltersChain, "-I"},
      {IpFamily::Dual, "filter", "FORWARD", kVpnEgressFiltersChain},
      {IpFamily::Dual, "filter", kVpnEgressFiltersChain, kVpnAcceptChain},
      {IpFamily::Dual, "filter", kVpnEgressFiltersChain, kVpnLockdownChain},
      // b/196898241: To ensure that the drop chains drop_guest_ipv4_prefix and
      // drop_guest_invalid_ipv4 chain are traversed before vpn_accept and
      // vpn_lockdown, they are inserted last in front of the OUTPUT chain and
      // FORWARD chains respectively.
      {IpFamily::IPv4, "filter", "OUTPUT", kDropGuestIpv4PrefixChain, "-I"},
      {IpFamily::IPv4, "filter", "FORWARD", kDropGuestInvalidIpv4Chain, "-I"},
      // Attach ingress and egress firewall chains for permission_broker rules.
      {IpFamily::Dual, "filter", "INPUT", kIngressPortFirewallChain},
      {IpFamily::Dual, "filter", "OUTPUT", kEgressPortFirewallChain},
  };
  for (const auto& c : jumpCommands) {
    std::string op = "-A";
    if (!c.op.empty()) {
      op = c.op;
    }
    if (!ModifyJumpRule(c.family, c.table, op, c.jump_from, c.jump_to,
                        "" /*iif*/, "" /*oif*/)) {
      LOG(ERROR) << "Failed to create jump rule from " << c.jump_from << " to "
                 << c.jump_to << " in " << c.table << " table";
    }
  }

  // Create a FORWARD ACCEPT rule for connections already established.
  if (process_runner_->iptables(
          "filter", {"-A", "FORWARD", "-m", "state", "--state",
                     "ESTABLISHED,RELATED", "-j", "ACCEPT", "-w"}) != 0) {
    LOG(ERROR) << "Failed to install forwarding rule for established"
               << " connections.";
  }

  // Create a FORWARD ACCEPT rule for ICMP6.
  if (process_runner_->ip6tables("filter", {"-A", "FORWARD", "-p", "ipv6-icmp",
                                            "-j", "ACCEPT", "-w"}) != 0)
    LOG(ERROR) << "Failed to install forwarding rule for ICMP6";

  // chromium:898210: Drop any locally originated traffic that would exit a
  // physical interface with a source IPv4 address from the subnet of IPs used
  // for VMs, containers, and connected namespaces This is needed to prevent
  // packets leaking with an incorrect src IP when a local process binds to the
  // wrong interface.
  for (const auto& oif : kPhysicalIfnamePrefixes) {
    if (!AddSourceIPv4DropRule(oif, kGuestIPv4Subnet)) {
      LOG(WARNING) << "Failed to set up IPv4 drop rule for src ip "
                   << kGuestIPv4Subnet << " exiting " << oif;
    }
  }

  // chromium:1050579: INVALID packets cannot be tracked by conntrack therefore
  // need to be explicitly dropped as SNAT cannot be applied to them.
  // b/196898241: To ensure that the INVALID DROP rule is traversed before
  // vpn_accept and vpn_lockdown, insert it in front of the FORWARD chain last.
  std::string snatMark =
      kFwmarkLegacySNAT.ToString() + "/" + kFwmarkLegacySNAT.ToString();
  if (process_runner_->iptables(
          "filter",
          {"-I", kDropGuestInvalidIpv4Chain, "-m", "mark", "--mark", snatMark,
           "-m", "state", "--state", "INVALID", "-j", "DROP", "-w"}) != 0) {
    LOG(ERROR) << "Failed to install FORWARD rule to drop INVALID packets";
  }
  // b/196899048: IPv4 TCP packets with TCP flags FIN,PSH coming from downstream
  // guests need to be dropped explicitly because SNAT will not apply to them
  // but the --state INVALID rule above will also not match for these packets.
  // crbug/1241756: Make sure that only egress FINPSH packets are dropped.
  for (const auto& oif : kCellularIfnamePrefixes) {
    if (process_runner_->iptables(
            "filter", {"-I", kDropGuestInvalidIpv4Chain, "-s", kGuestIPv4Subnet,
                       "-p", "tcp", "--tcp-flags", "FIN,PSH", "FIN,PSH", "-o",
                       oif, "-j", "DROP", "-w"}) != 0) {
      LOG(ERROR) << "Failed to install FORWARD rule to drop TCP FIN,PSH "
                    "packets egressing "
                 << oif << " interfaces";
    }
  }

  // Set static SNAT rules for any IPv4 traffic originated from a guest (ARC,
  // Crostini, ...) or a connected namespace.
  if (process_runner_->iptables(
          "nat", {"-A", "POSTROUTING", "-m", "mark", "--mark", snatMark, "-j",
                  "MASQUERADE", "-w"}) != 0) {
    LOG(ERROR) << "Failed to install SNAT mark rules.";
  }

  // Applies the routing tag saved in conntrack for any established connection
  // for sockets created in the host network namespace.
  if (!ModifyConnmarkRestore(IpFamily::Dual, "OUTPUT", "-A", "" /*iif*/,
                             kFwmarkRoutingMask)) {
    LOG(ERROR) << "Failed to add OUTPUT CONNMARK restore rule";
  }

  // Add a rule for skipping apply_local_source_mark if the packet already has a
  // source mark (e.g., packets from a wireguard socket in the kernel).
  // TODO(b/190683881): This will also skip setting VPN policy bits on the
  // packet. Currently this rule will only be triggered for wireguard sockets so
  // it has no side effect now. We may need to revisit this later.
  ModifyIptables(
      IpFamily::Dual, "mangle",
      {"-A", kApplyLocalSourceMarkChain, "-m", "mark", "!", "--mark",
       "0x0/" + kFwmarkAllSourcesMask.ToString(), "-j", "RETURN", "-w"});
  // Create rules for tagging local sources with the source tag and the vpn
  // policy tag.
  for (const auto& source : kLocalSourceTypes) {
    if (!ModifyFwmarkLocalSourceTag("-A", source)) {
      LOG(ERROR) << "Failed to create fwmark tagging rule for uid " << source
                 << " in " << kApplyLocalSourceMarkChain;
    }
  }
  // Finally add a catch-all rule for tagging any remaining local sources with
  // the SYSTEM source tag
  if (!ModifyFwmarkDefaultLocalSourceTag("-A", TrafficSource::SYSTEM))
    LOG(ERROR) << "Failed to set up rule tagging traffic with default source";

  // Set up jump chains to the DNS nat chains for egress traffic from local
  // processes running on the host.
  if (!ModifyRedirectDnsJumpRule(IpFamily::Dual, "-A", "OUTPUT",
                                 "" /* ifname */, kRedirectChromeDnsChain)) {
    LOG(ERROR) << "Failed to add jump rule for chrome DNS redirection";
  }
  if (!ModifyRedirectDnsJumpRule(IpFamily::Dual, "-A", "OUTPUT",
                                 "" /* ifname */, kRedirectUserDnsChain,
                                 kFwmarkRouteOnVpn, kFwmarkVpnMask,
                                 true /* redirect_on_mark */)) {
    LOG(ERROR) << "Failed to add jump rule for user DNS redirection";
  }
  if (!ModifyRedirectDnsJumpRule(
          IpFamily::Dual, "-A", "POSTROUTING", "" /* ifname */,
          kSnatChromeDnsChain, Fwmark::FromSource(TrafficSource::CHROME),
          kFwmarkAllSourcesMask, true /* redirect_on_mark */)) {
    LOG(ERROR) << "Failed to add jump rule for chrome DNS SNAT";
  }
  if (!ModifyRedirectDnsJumpRule(IpFamily::IPv6, "-A", "POSTROUTING",
                                 "" /* ifname */, kSnatUserDnsChain,
                                 kFwmarkRouteOnVpn, kFwmarkVpnMask,
                                 true /* redirect_on_mark */)) {
    LOG(ERROR) << "Failed to add jump rule for user DNS SNAT";
  }

  // All local outgoing DNS traffic eligible to VPN routing should skip the VPN
  // routing chain and instead go through DNS proxy.
  if (!ModifyFwmarkSkipVpnJumpRule("OUTPUT", "-A", kChronosUid)) {
    LOG(ERROR) << "Failed to add jump rule to skip VPN mark chain in mangle "
               << "OUTPUT chain";
  }

  // All local outgoing traffic eligible to VPN routing should traverse the VPN
  // marking chain.
  if (!ModifyFwmarkVpnJumpRule("OUTPUT", "-A", kFwmarkRouteOnVpn,
                               kFwmarkVpnMask)) {
    LOG(ERROR) << "Failed to add jump rule to VPN chain in mangle OUTPUT chain";
  }

  // b/176260499: on 4.4 kernel, the following connmark rules are observed to
  // incorrectly cause neighbor discovery icmpv6 packets to be dropped. Add
  // these rules to bypass connmark rule for those packets.
  for (const auto& type : kNeighborDiscoveryTypes) {
    if (!ModifyIptables(IpFamily::IPv6, "mangle",
                        {"-I", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", type,
                         "-j", "ACCEPT", "-w"})) {
      LOG(ERROR) << "Failed to set up connmark bypass rule for " << type
                 << " packets in OUTPUT";
    }
  }
}

void Datapath::Stop() {
  // Restore original local port range.
  // TODO(garrick): The original history behind this tweak is gone. Some
  // investigation is needed to see if it is still applicable.
  if (!system_->SysNetSet(System::SysNet::IPLocalPortRange, "32768 61000")) {
    LOG(ERROR) << "Failed to restore local port range";
  }

  // Disable packet forwarding
  if (!system_->SysNetSet(System::SysNet::IPv6Forward, "0"))
    LOG(ERROR) << "Failed to restore net.ipv6.conf.all.forwarding.";

  if (!system_->SysNetSet(System::SysNet::IPv4Forward, "0"))
    LOG(ERROR) << "Failed to restore net.ipv4.ip_forward.";

  ResetIptables();
}

void Datapath::ResetIptables() {
  // If they exists, remove jump rules from built-in chains to custom chains
  // for any built-in chains that is not explicitly flushed.
  ModifyJumpRule(IpFamily::IPv4, "filter", "-D", "OUTPUT",
                 kDropGuestIpv4PrefixChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyJumpRule(IpFamily::Dual, "filter", "-D", "INPUT",
                 kIngressPortFirewallChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyJumpRule(IpFamily::Dual, "filter", "-D", "OUTPUT",
                 kEgressPortFirewallChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyJumpRule(IpFamily::IPv4, "nat", "-D", "PREROUTING",
                 kIngressPortForwardingChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyJumpRule(IpFamily::IPv4, "nat", "-D", "PREROUTING",
                 kIngressDefaultForwardingChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyJumpRule(IpFamily::Dual, "nat", "-D", "PREROUTING",
                 kRedirectDefaultDnsChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyJumpRule(IpFamily::Dual, "nat", "-D", "PREROUTING",
                 kRedirectArcDnsChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);
  ModifyFwmarkSkipVpnJumpRule("OUTPUT", "-D", kChronosUid,
                              false /*log_failures*/);
  ModifyJumpRule(IpFamily::Dual, "filter", "-D", "OUTPUT",
                 kVpnEgressFiltersChain, "" /*iif*/, "" /*oif*/,
                 false /*log_failures*/);

  // Flush chains used for routing and fwmark tagging. Also delete additional
  // chains made by patchpanel. Chains used by permission broker (nat
  // PREROUTING, filter INPUT) and chains used for traffic counters (mangle
  // {rx,tx}_{<iface>, vpn}) are not flushed.
  // If there is any jump rule between from a chain to another chain that must
  // be removed, the first chain must be flushed first.
  // The "ingress_port_forwarding" chain is not flushed since it must hold port
  // forwarding rules requested by permission_broker.
  static struct {
    IpFamily family;
    std::string table;
    std::string chain;
    bool should_delete;
  } resetOps[] = {
      {IpFamily::Dual, "filter", "FORWARD", false},
      {IpFamily::Dual, "mangle", "FORWARD", false},
      {IpFamily::Dual, "mangle", "INPUT", false},
      {IpFamily::Dual, "mangle", "OUTPUT", false},
      {IpFamily::Dual, "mangle", "POSTROUTING", false},
      {IpFamily::Dual, "mangle", "PREROUTING", false},
      {IpFamily::Dual, "mangle", kApplyLocalSourceMarkChain, true},
      {IpFamily::Dual, "mangle", kApplyVpnMarkChain, true},
      {IpFamily::Dual, "mangle", kSkipApplyVpnMarkChain, true},
      {IpFamily::IPv4, "filter", kDropGuestIpv4PrefixChain, true},
      {IpFamily::IPv4, "filter", kDropGuestInvalidIpv4Chain, true},
      {IpFamily::Dual, "filter", kVpnEgressFiltersChain, true},
      {IpFamily::Dual, "filter", kVpnAcceptChain, true},
      {IpFamily::Dual, "filter", kVpnLockdownChain, true},
      {IpFamily::Dual, "nat", "OUTPUT", false},
      {IpFamily::IPv4, "nat", "POSTROUTING", false},
      {IpFamily::Dual, "nat", kRedirectDefaultDnsChain, true},
      {IpFamily::Dual, "nat", kRedirectArcDnsChain, true},
      {IpFamily::Dual, "nat", kRedirectChromeDnsChain, true},
      {IpFamily::Dual, "nat", kRedirectUserDnsChain, true},
      {IpFamily::Dual, "nat", kSnatChromeDnsChain, true},
      {IpFamily::IPv6, "nat", kSnatUserDnsChain, true},
      {IpFamily::IPv4, "nat", kRedirectDnsChain, true},
      {IpFamily::IPv4, "nat", kIngressDefaultForwardingChain, true},
  };
  for (const auto& op : resetOps) {
    // Chains to delete are custom chains and will not exist the first time
    // patchpanel starts after boot. Skip flushing and delete these chains if
    // they do not exist to avoid logging spurious error messages.
    if (op.should_delete && !ModifyChain(op.family, op.table, "-L", op.chain,
                                         false /*log_failures*/)) {
      continue;
    }

    if (!FlushChain(op.family, op.table, op.chain)) {
      LOG(ERROR) << "Failed to flush " << op.chain << " chain in table "
                 << op.table;
    }

    if (op.should_delete && !RemoveChain(op.family, op.table, op.chain)) {
      LOG(ERROR) << "Failed to delete " << op.chain << " chain in table "
                 << op.table;
    }
  }
}

bool Datapath::NetnsAttachName(const std::string& netns_name, pid_t netns_pid) {
  // Try first to delete any netns with name |netns_name| in case patchpanel
  // did not exit cleanly.
  if (process_runner_->ip_netns_delete(netns_name, false /*log_failures*/) == 0)
    LOG(INFO) << "Deleted left over network namespace name " << netns_name;

  if (netns_pid == ConnectedNamespace::kNewNetnsPid)
    return process_runner_->ip_netns_add(netns_name) == 0;
  else
    return process_runner_->ip_netns_attach(netns_name, netns_pid) == 0;
}

bool Datapath::NetnsDeleteName(const std::string& netns_name) {
  return process_runner_->ip_netns_delete(netns_name) == 0;
}

bool Datapath::AddBridge(const std::string& ifname,
                         uint32_t ipv4_addr,
                         uint32_t ipv4_prefix_len) {
  if (!Ioctl(system_, SIOCBRADDBR, ifname.c_str())) {
    LOG(ERROR) << "Failed to create bridge " << ifname;
    return false;
  }

  // Configure the persistent Chrome OS bridge interface with static IP.
  if (process_runner_->ip(
          "addr", "add",
          {IPv4AddressToCidrString(ipv4_addr, ipv4_prefix_len), "brd",
           IPv4AddressToString(Ipv4BroadcastAddr(ipv4_addr, ipv4_prefix_len)),
           "dev", ifname}) != 0) {
    RemoveBridge(ifname);
    return false;
  }

  if (process_runner_->ip("link", "set", {ifname, "up"}) != 0) {
    RemoveBridge(ifname);
    return false;
  }

  return true;
}

void Datapath::RemoveBridge(const std::string& ifname) {
  process_runner_->ip("link", "set", {ifname, "down"});
  if (!Ioctl(system_, SIOCBRDELBR, ifname.c_str()))
    LOG(ERROR) << "Failed to destroy bridge " << ifname;
}

bool Datapath::AddToBridge(const std::string& br_ifname,
                           const std::string& ifname) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, br_ifname.c_str(), sizeof(ifr.ifr_name));
  ifr.ifr_ifindex = system_->IfNametoindex(ifname);

  if (!Ioctl(system_, SIOCBRADDIF, reinterpret_cast<const char*>(&ifr))) {
    LOG(ERROR) << "Failed to add " << ifname << " to bridge " << br_ifname;
    return false;
  }

  return true;
}

std::string Datapath::AddTAP(const std::string& name,
                             const MacAddress* mac_addr,
                             const SubnetAddress* ipv4_addr,
                             const std::string& user) {
  base::ScopedFD dev(open(kTunDev, O_RDWR | O_NONBLOCK));
  if (!dev.is_valid()) {
    PLOG(ERROR) << "Failed to open " << kTunDev;
    return "";
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, name.empty() ? kDefaultIfname : name.c_str(),
          sizeof(ifr.ifr_name));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  // If a template was given as the name, ifr_name will be updated with the
  // actual interface name.
  if (system_->Ioctl(dev.get(), TUNSETIFF, &ifr) != 0) {
    PLOG(ERROR) << "Failed to create tap interface " << name;
    return "";
  }
  const char* ifname = ifr.ifr_name;

  if (system_->Ioctl(dev.get(), TUNSETPERSIST, 1) != 0) {
    PLOG(ERROR) << "Failed to persist the interface " << ifname;
    return "";
  }

  if (!user.empty()) {
    uid_t uid = -1;
    if (!brillo::userdb::GetUserInfo(user, &uid, nullptr)) {
      PLOG(ERROR) << "Unable to look up UID for " << user;
      RemoveTAP(ifname);
      return "";
    }
    if (system_->Ioctl(dev.get(), TUNSETOWNER, uid) != 0) {
      PLOG(ERROR) << "Failed to set owner " << uid << " of tap interface "
                  << ifname;
      RemoveTAP(ifname);
      return "";
    }
  }

  // Create control socket for configuring the interface.
  base::ScopedFD sock(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (!sock.is_valid()) {
    PLOG(ERROR) << "Failed to create control socket for tap interface "
                << ifname;
    RemoveTAP(ifname);
    return "";
  }

  if (ipv4_addr) {
    struct sockaddr_in* addr =
        reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = static_cast<in_addr_t>(ipv4_addr->Address());
    if (system_->Ioctl(sock.get(), SIOCSIFADDR, &ifr) != 0) {
      PLOG(ERROR) << "Failed to set ip address for vmtap interface " << ifname
                  << " {" << ipv4_addr->ToCidrString() << "}";
      RemoveTAP(ifname);
      return "";
    }

    struct sockaddr_in* netmask =
        reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
    netmask->sin_family = AF_INET;
    netmask->sin_addr.s_addr = static_cast<in_addr_t>(ipv4_addr->Netmask());
    if (system_->Ioctl(sock.get(), SIOCSIFNETMASK, &ifr) != 0) {
      PLOG(ERROR) << "Failed to set netmask for vmtap interface " << ifname
                  << " {" << ipv4_addr->ToCidrString() << "}";
      RemoveTAP(ifname);
      return "";
    }
  }

  if (mac_addr) {
    struct sockaddr* hwaddr = &ifr.ifr_hwaddr;
    hwaddr->sa_family = ARPHRD_ETHER;
    memcpy(&hwaddr->sa_data, mac_addr, sizeof(*mac_addr));
    if (system_->Ioctl(sock.get(), SIOCSIFHWADDR, &ifr) != 0) {
      PLOG(ERROR) << "Failed to set mac address for vmtap interface " << ifname
                  << " {" << MacAddressToString(*mac_addr) << "}";
      RemoveTAP(ifname);
      return "";
    }
  }

  if (system_->Ioctl(sock.get(), SIOCGIFFLAGS, &ifr) != 0) {
    PLOG(ERROR) << "Failed to get flags for tap interface " << ifname;
    RemoveTAP(ifname);
    return "";
  }

  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  if (system_->Ioctl(sock.get(), SIOCSIFFLAGS, &ifr) != 0) {
    PLOG(ERROR) << "Failed to enable tap interface " << ifname;
    RemoveTAP(ifname);
    return "";
  }

  return ifname;
}

void Datapath::RemoveTAP(const std::string& ifname) {
  process_runner_->ip("tuntap", "del", {ifname, "mode", "tap"});
}

bool Datapath::ConnectVethPair(pid_t netns_pid,
                               const std::string& netns_name,
                               const std::string& veth_ifname,
                               const std::string& peer_ifname,
                               const MacAddress& remote_mac_addr,
                               uint32_t remote_ipv4_addr,
                               uint32_t remote_ipv4_prefix_len,
                               bool remote_multicast_flag) {
  // Set up the virtual pair across the current namespace and |netns_name|.
  if (!AddVirtualInterfacePair(netns_name, veth_ifname, peer_ifname)) {
    LOG(ERROR) << "Failed to create veth pair " << veth_ifname << ","
               << peer_ifname;
    return false;
  }

  // Configure the remote veth in namespace |netns_name|.
  {
    auto ns = ScopedNS::EnterNetworkNS(netns_name);
    if (!ns && netns_pid != kTestPID) {
      LOG(ERROR)
          << "Cannot create virtual link -- invalid container namespace?";
      return false;
    }

    if (!ConfigureInterface(peer_ifname, remote_mac_addr, remote_ipv4_addr,
                            remote_ipv4_prefix_len, true /* link up */,
                            remote_multicast_flag)) {
      LOG(ERROR) << "Failed to configure interface " << peer_ifname;
      RemoveInterface(peer_ifname);
      return false;
    }
  }

  if (!ToggleInterface(veth_ifname, true /*up*/)) {
    LOG(ERROR) << "Failed to bring up interface " << veth_ifname;
    RemoveInterface(veth_ifname);
    return false;
  }

  return true;
}

void Datapath::RestartIPv6() {
  if (!system_->SysNetSet(System::SysNet::IPv6Disable, "1")) {
    LOG(ERROR) << "Failed to disable IPv6";
  }
  if (!system_->SysNetSet(System::SysNet::IPv6Disable, "0")) {
    LOG(ERROR) << "Failed to re-enable IPv6";
  }
}

bool Datapath::AddVirtualInterfacePair(const std::string& netns_name,
                                       const std::string& veth_ifname,
                                       const std::string& peer_ifname) {
  return process_runner_->ip("link", "add",
                             {veth_ifname, "type", "veth", "peer", "name",
                              peer_ifname, "netns", netns_name}) == 0;
}

bool Datapath::ToggleInterface(const std::string& ifname, bool up) {
  const std::string link = up ? "up" : "down";
  return process_runner_->ip("link", "set", {ifname, link}) == 0;
}

bool Datapath::ConfigureInterface(const std::string& ifname,
                                  const MacAddress& mac_addr,
                                  uint32_t ipv4_addr,
                                  uint32_t ipv4_prefix_len,
                                  bool up,
                                  bool enable_multicast) {
  const std::string link = up ? "up" : "down";
  const std::string multicast = enable_multicast ? "on" : "off";
  return (process_runner_->ip(
              "addr", "add",
              {IPv4AddressToCidrString(ipv4_addr, ipv4_prefix_len), "brd",
               IPv4AddressToString(
                   Ipv4BroadcastAddr(ipv4_addr, ipv4_prefix_len)),
               "dev", ifname}) == 0) &&
         (process_runner_->ip("link", "set",
                              {
                                  "dev",
                                  ifname,
                                  link,
                                  "addr",
                                  MacAddressToString(mac_addr),
                                  "multicast",
                                  multicast,
                              }) == 0);
}

void Datapath::RemoveInterface(const std::string& ifname) {
  process_runner_->ip("link", "delete", {ifname}, false /*log_failures*/);
}

bool Datapath::AddSourceIPv4DropRule(const std::string& oif,
                                     const std::string& src_ip) {
  return process_runner_->iptables(
             "filter", {"-I", kDropGuestIpv4PrefixChain, "-o", oif, "-s",
                        src_ip, "-j", "DROP", "-w"}) == 0;
}

bool Datapath::StartRoutingNamespace(const ConnectedNamespace& nsinfo) {
  // Veth interface configuration and client routing configuration:
  //  - attach a name to the client namespace (or create a new named namespace
  //    if no client is specified).
  //  - create veth pair across the current namespace and the client namespace.
  //  - configure IPv4 address on remote veth inside client namespace.
  //  - configure IPv4 address on local veth inside host namespace.
  //  - add a default IPv4 /0 route sending traffic to that remote veth.
  if (!NetnsAttachName(nsinfo.netns_name, nsinfo.pid)) {
    LOG(ERROR) << "Failed to attach name " << nsinfo.netns_name
               << " to namespace pid " << nsinfo.pid;
    return false;
  }

  if (!ConnectVethPair(
          nsinfo.pid, nsinfo.netns_name, nsinfo.host_ifname, nsinfo.peer_ifname,
          nsinfo.peer_mac_addr, nsinfo.peer_subnet->AddressAtOffset(1),
          nsinfo.peer_subnet->PrefixLength(), false /* enable_multicast */)) {
    LOG(ERROR) << "Failed to create veth pair for"
                  " namespace pid "
               << nsinfo.pid;
    NetnsDeleteName(nsinfo.netns_name);
    return false;
  }

  if (!ConfigureInterface(nsinfo.host_ifname, nsinfo.host_mac_addr,
                          nsinfo.peer_subnet->AddressAtOffset(0),
                          nsinfo.peer_subnet->PrefixLength(),
                          true /* link up */, false /* enable_multicast */)) {
    LOG(ERROR) << "Cannot configure host interface " << nsinfo.host_ifname;
    RemoveInterface(nsinfo.host_ifname);
    NetnsDeleteName(nsinfo.netns_name);
    return false;
  }

  {
    auto ns = ScopedNS::EnterNetworkNS(nsinfo.netns_name);
    if (!ns && nsinfo.pid != kTestPID) {
      LOG(ERROR) << "Invalid namespace pid " << nsinfo.pid;
      RemoveInterface(nsinfo.host_ifname);
      NetnsDeleteName(nsinfo.netns_name);
      return false;
    }

    if (!AddIPv4Route(nsinfo.peer_subnet->AddressAtOffset(0), INADDR_ANY,
                      INADDR_ANY)) {
      LOG(ERROR) << "Failed to add default /0 route to " << nsinfo.host_ifname
                 << " inside namespace pid " << nsinfo.pid;
      RemoveInterface(nsinfo.host_ifname);
      NetnsDeleteName(nsinfo.netns_name);
      return false;
    }
  }

  // Host namespace routing configuration
  //  - ingress: add route to client subnet via |host_ifname|.
  //  - egress: - allow forwarding for traffic outgoing |host_ifname|.
  //            - add SNAT mark 0x1/0x1 for traffic outgoing |host_ifname|.
  //  Note that by default unsolicited ingress traffic is not forwarded to the
  //  client namespace unless the client specifically set port forwarding
  //  through permission_broker DBus APIs.
  // TODO(hugobenichi) If allow_user_traffic is false, then prevent forwarding
  // both ways between client namespace and other guest containers and VMs.
  uint32_t netmask = Ipv4Netmask(nsinfo.peer_subnet->PrefixLength());
  if (!AddIPv4Route(nsinfo.peer_subnet->AddressAtOffset(0),
                    nsinfo.peer_subnet->BaseAddress(), netmask)) {
    LOG(ERROR) << "Failed to set route to client namespace";
    RemoveInterface(nsinfo.host_ifname);
    NetnsDeleteName(nsinfo.netns_name);
    return false;
  }

  StartRoutingDevice(nsinfo.outbound_ifname, nsinfo.host_ifname,
                     nsinfo.peer_subnet->AddressAtOffset(0), nsinfo.source,
                     nsinfo.route_on_vpn,
                     nsinfo.peer_subnet->AddressAtOffset(1));
  return true;
}

void Datapath::StopRoutingNamespace(const ConnectedNamespace& nsinfo) {
  StopRoutingDevice(nsinfo.outbound_ifname, nsinfo.host_ifname,
                    nsinfo.peer_subnet->AddressAtOffset(0), nsinfo.source,
                    nsinfo.route_on_vpn);
  RemoveInterface(nsinfo.host_ifname);
  DeleteIPv4Route(nsinfo.peer_subnet->AddressAtOffset(0),
                  nsinfo.peer_subnet->BaseAddress(),
                  Ipv4Netmask(nsinfo.peer_subnet->PrefixLength()));
  NetnsDeleteName(nsinfo.netns_name);
}

bool Datapath::ModifyChromeDnsRedirect(IpFamily family,
                                       const DnsRedirectionRule& rule,
                                       const std::string& op) {
  // Validate nameservers.
  for (const auto& nameserver : rule.nameservers) {
    sa_family_t sa_family = GetIpFamily(rule.proxy_address);
    switch (sa_family) {
      case AF_INET:
        if (family != IpFamily::IPv4) {
          LOG(ERROR) << "Invalid nameserver IPv4 address '" << nameserver
                     << "'";
          return false;
        }
        break;
      case AF_INET6:
        if (family != IpFamily::IPv6) {
          LOG(ERROR) << "Invalid nameserver IPv6 address '" << nameserver
                     << "'";
          return false;
        }
        break;
      default:
        LOG(ERROR) << "Invalid IP family " << family;
        return false;
    }
  }

  bool success = true;
  for (const auto& protocol : {"udp", "tcp"}) {
    for (int i = 0; i < rule.nameservers.size(); i++) {
      std::vector<std::string> args{
          op,
          kRedirectChromeDnsChain,
          "-p",
      };
      args.push_back(protocol);
      args.push_back("--dport");  // input destination port
      args.push_back(kDefaultDnsPort);
      args.push_back("-m");
      args.push_back("owner");
      args.push_back("--uid-owner");
      args.push_back(kChronosUid);

      // If there are multiple destination IPs, forward to them in a round robin
      // fashion with statistics module.
      if (rule.nameservers.size() > 1) {
        args.push_back("-m");
        args.push_back("statistic");
        args.push_back("--mode");
        args.push_back("nth");
        args.push_back("--every");
        args.push_back(std::to_string(i + 1));
        args.push_back("--packet");
        args.push_back("0");
      }
      args.push_back("-j");
      args.push_back("DNAT");
      args.push_back("--to-destination");
      args.push_back(rule.nameservers[i]);
      args.push_back("-w");  // Wait for xtables lock.
      if (!ModifyIptables(family, "nat", args)) {
        success = false;
      }
    }
  }
  if (!ModifyDnsProxyMasquerade(family, op, kSnatChromeDnsChain)) {
    success = false;
  }
  return success;
}

bool Datapath::ModifyDnsProxyDNAT(IpFamily family,
                                  const DnsRedirectionRule& rule,
                                  const std::string& op,
                                  const std::string& ifname,
                                  const std::string& chain) {
  bool success = true;
  for (const auto& protocol : {"udp", "tcp"}) {
    std::vector<std::string> args = {op, chain};
    if (!ifname.empty()) {
      args.insert(args.end(), {"-i", ifname});
    }
    args.push_back("-p");
    args.push_back(protocol);
    args.push_back("--dport");
    args.push_back(kDefaultDnsPort);
    args.push_back("-j");
    args.push_back("DNAT");
    args.push_back("--to-destination");
    args.push_back(rule.proxy_address);
    args.push_back("-w");
    if (!ModifyIptables(family, "nat", args)) {
      success = false;
    }
  }
  return success;
}

bool Datapath::ModifyDnsProxyMasquerade(IpFamily family,
                                        const std::string& op,
                                        const std::string& chain) {
  bool success = true;
  for (const auto& protocol : {"udp", "tcp"}) {
    std::vector<std::string> args = {op,       chain,        "-p",
                                     protocol, "--dport",    kDefaultDnsPort,
                                     "-j",     "MASQUERADE", "-w"};
    if (!ModifyIptables(family, "nat", args)) {
      success = false;
    }
  }
  return success;
}

bool Datapath::StartDnsRedirection(const DnsRedirectionRule& rule) {
  IpFamily family;
  sa_family_t sa_family = GetIpFamily(rule.proxy_address);
  switch (sa_family) {
    case AF_INET:
      family = IpFamily::IPv4;
      break;
    case AF_INET6:
      family = IpFamily::IPv6;
      break;
    default:
      LOG(ERROR) << "Invalid proxy address " << rule.proxy_address;
      return false;
  }

  switch (rule.type) {
    case patchpanel::SetDnsRedirectionRuleRequest::DEFAULT: {
      if (!ModifyDnsProxyDNAT(family, rule, "-I", rule.input_ifname,
                              kRedirectDefaultDnsChain)) {
        LOG(ERROR) << "Failed to add DNS DNAT rule for " << rule.input_ifname;
        return false;
      }
      return true;
    }
    case patchpanel::SetDnsRedirectionRuleRequest::ARC: {
      if (!ModifyDnsProxyDNAT(family, rule, "-I", rule.input_ifname,
                              kRedirectArcDnsChain)) {
        LOG(ERROR) << "Failed to add DNS DNAT rule for " << rule.input_ifname;
        return false;
      }
      return true;
    }
    case patchpanel::SetDnsRedirectionRuleRequest::USER: {
      // Start protecting DNS traffic from VPN fwmark tagging.
      if (!ModifyDnsRedirectionSkipVpnRule(family, "-A")) {
        LOG(ERROR) << "Failed to add VPN skip rule for DNS proxy";
        return false;
      }

      // Add DNS redirect rules for chrome traffic.
      if (!ModifyChromeDnsRedirect(family, rule, "-I")) {
        LOG(ERROR) << "Failed to add chrome DNS DNAT rule";
        return false;
      }

      // Add DNS redirect rule for user traffic.
      if (!ModifyDnsProxyDNAT(family, rule, "-A", "" /* ifname */,
                              kRedirectUserDnsChain)) {
        LOG(ERROR) << "Failed to add user DNS DNAT rule";
        return false;
      }

      // Add MASQUERADE rule for user traffic.
      if (family == IpFamily::IPv6 &&
          !ModifyDnsProxyMasquerade(family, "-A", kSnatUserDnsChain)) {
        LOG(ERROR) << "Failed to add user DNS MASQUERADE rule";
        return false;
      }
      return true;
    }
    default:
      LOG(ERROR) << "Invalid DNS proxy type " << rule;
      return false;
  }
}

void Datapath::StopDnsRedirection(const DnsRedirectionRule& rule) {
  IpFamily family;
  sa_family_t sa_family = GetIpFamily(rule.proxy_address);
  switch (sa_family) {
    case AF_INET:
      family = IpFamily::IPv4;
      break;
    case AF_INET6:
      family = IpFamily::IPv6;
      break;
    default:
      LOG(ERROR) << "Invalid proxy address " << rule.proxy_address;
      return;
  }

  // Whenever the client that requested the rule closes the fd, the requested
  // rule will be deleted. There is a delay between fd closing time and rule
  // removal time. This prevents deletion of the rules by flushing the chains.
  switch (rule.type) {
    case patchpanel::SetDnsRedirectionRuleRequest::DEFAULT: {
      ModifyDnsProxyDNAT(family, rule, "-D", rule.input_ifname,
                         kRedirectDefaultDnsChain);
      break;
    }
    case patchpanel::SetDnsRedirectionRuleRequest::ARC: {
      ModifyDnsProxyDNAT(family, rule, "-D", rule.input_ifname,
                         kRedirectArcDnsChain);
      break;
    }
    case patchpanel::SetDnsRedirectionRuleRequest::USER: {
      ModifyChromeDnsRedirect(family, rule, "-D");
      ModifyDnsProxyDNAT(family, rule, "-D", "" /* ifname */,
                         kRedirectUserDnsChain);
      ModifyDnsRedirectionSkipVpnRule(family, "-D");
      if (family == IpFamily::IPv6) {
        ModifyDnsProxyMasquerade(family, "-D", kSnatUserDnsChain);
      }
      break;
    }
    default:
      LOG(ERROR) << "Invalid DNS proxy type " << rule;
  }
}

void Datapath::StartRoutingDevice(const std::string& ext_ifname,
                                  const std::string& int_ifname,
                                  uint32_t int_ipv4_addr,
                                  TrafficSource source,
                                  bool route_on_vpn,
                                  uint32_t peer_ipv4_addr) {
  if (!ModifyJumpRule(IpFamily::Dual, "filter", "-A", "FORWARD", "ACCEPT",
                      "" /*iif*/, int_ifname)) {
    LOG(ERROR) << "Failed to enable IP forwarding from " << ext_ifname;
  }

  if (!ModifyJumpRule(IpFamily::Dual, "filter", "-A", "FORWARD", "ACCEPT",
                      int_ifname, "" /*oif*/)) {
    LOG(ERROR) << "Failed to enable IP forwarding to " << ext_ifname;
  }

  std::string subchain = "PREROUTING_" + int_ifname;
  // This can fail if patchpanel did not stopped correctly or failed to cleanup
  // the chain when |int_ifname| was previously deleted.
  if (!AddChain(IpFamily::Dual, "mangle", subchain))
    LOG(ERROR) << "Failed to create mangle chain " << subchain;
  // Make sure the chain is empty if patchpanel did not cleaned correctly that
  // chain before.
  if (!FlushChain(IpFamily::Dual, "mangle", subchain)) {
    LOG(ERROR) << "Could not flush " << subchain;
  }
  if (!ModifyJumpRule(IpFamily::Dual, "mangle", "-A", "PREROUTING", subchain,
                      int_ifname, "" /*oif*/)) {
    LOG(ERROR) << "Could not add jump rule from mangle PREROUTING to "
               << subchain;
  }
  // IPv4 traffic from all downstream interfaces should be tagged to go through
  // SNAT.
  if (!ModifyFwmark(IpFamily::IPv4, subchain, "-A", "", "", 0,
                    kFwmarkLegacySNAT, kFwmarkLegacySNAT)) {
    LOG(ERROR) << "Failed to add fwmark SNAT tagging rule for " << int_ifname;
  }
  if (!ModifyFwmarkSourceTag(subchain, "-A", source)) {
    LOG(ERROR) << "Failed to add fwmark tagging rule for source " << source
               << " in " << subchain;
  }

  if (!ext_ifname.empty()) {
    // If |ext_ifname| is not null, mark egress traffic with the
    // fwmark routing tag corresponding to |ext_ifname|.
    int ifindex = system_->IfNametoindex(ext_ifname);
    if (ifindex == 0) {
      LOG(ERROR) << "Failed to retrieve interface index of " << ext_ifname;
      return;
    }
    if (!ModifyFwmarkRoutingTag(subchain, "-A", Fwmark::FromIfIndex(ifindex))) {
      LOG(ERROR) << "Failed to add fwmark routing tag for " << ext_ifname
                 << "<-" << int_ifname << " in " << subchain;
    }
  } else {
    // Otherwise if ext_ifname is null, set up a CONNMARK restore rule in
    // PREROUTING to apply any fwmark routing tag saved for the current
    // connection, and rely on implicit routing to the default logical network
    // otherwise.
    if (!ModifyConnmarkRestore(IpFamily::Dual, subchain, "-A", "" /*iif*/,
                               kFwmarkRoutingMask)) {
      LOG(ERROR) << "Failed to add CONNMARK restore rule in " << subchain;
    }

    // Explicitly bypass VPN fwmark tagging rules on returning traffic of a
    // connected namespace. This allows the return traffic to reach the local
    // source. Connected namespace interface can be identified by checking if
    // the value of |peer_ipv4_addr| not equal to 0.
    if (route_on_vpn && peer_ipv4_addr != 0 &&
        process_runner_->iptables(
            "mangle",
            {"-A", subchain, "-s", IPv4AddressToString(peer_ipv4_addr), "-d",
             IPv4AddressToString(int_ipv4_addr), "-j", "ACCEPT", "-w"}) != 0) {
      LOG(ERROR) << "Failed to add connected namespace IPv4 VPN bypass rule";
    }

    // The jump rule below should not be applied for traffic from a
    // ConnectNamespace traffic that needs DNS to go to the VPN
    // (ConnectNamespace of the DNS default instance).
    if (route_on_vpn && peer_ipv4_addr == 0 &&
        !ModifyJumpRule(IpFamily::Dual, "mangle", "-A", subchain,
                        kSkipApplyVpnMarkChain, "" /*iif*/, "" /*oif*/)) {
      LOG(ERROR) << "Failed to add jump rule to DNS proxy VPN chain for "
                 << int_ifname;
    }

    // Forwarded traffic from downstream interfaces routed to the system
    // default network is eligible to be routed through a VPN if |route_on_vpn|
    // is true.
    if (route_on_vpn && !ModifyFwmarkVpnJumpRule(subchain, "-A", {}, {}))
      LOG(ERROR) << "Failed to add jump rule to VPN chain for " << int_ifname;
  }
}

void Datapath::StopRoutingDevice(const std::string& ext_ifname,
                                 const std::string& int_ifname,
                                 uint32_t int_ipv4_addr,
                                 TrafficSource source,
                                 bool route_on_vpn) {
  ModifyJumpRule(IpFamily::Dual, "filter", "-D", "FORWARD", "ACCEPT",
                 "" /*iif*/, int_ifname);
  ModifyJumpRule(IpFamily::Dual, "filter", "-D", "FORWARD", "ACCEPT",
                 int_ifname, "" /*oif*/);

  std::string subchain = "PREROUTING_" + int_ifname;
  ModifyJumpRule(IpFamily::Dual, "mangle", "-D", "PREROUTING", subchain,
                 int_ifname, "" /*oif*/);
  FlushChain(IpFamily::Dual, "mangle", subchain);
  RemoveChain(IpFamily::Dual, "mangle", subchain);
}

void Datapath::AddInboundIPv4DNAT(const std::string& ifname,
                                  const std::string& ipv4_addr) {
  // Direct ingress IP traffic to existing sockets.
  bool success = true;
  if (process_runner_->iptables(
          "nat", {"-A", kIngressDefaultForwardingChain, "-i", ifname, "-m",
                  "socket", "--nowildcard", "-j", "ACCEPT", "-w"}) != 0) {
    success = false;
  }

  // Direct ingress TCP & UDP traffic to ARC interface for new connections.
  if (process_runner_->iptables(
          "nat", {"-A", kIngressDefaultForwardingChain, "-i", ifname, "-p",
                  "tcp", "-j", "DNAT", "--to-destination", ipv4_addr, "-w"}) !=
      0) {
    success = false;
  }
  if (process_runner_->iptables(
          "nat", {"-A", kIngressDefaultForwardingChain, "-i", ifname, "-p",
                  "udp", "-j", "DNAT", "--to-destination", ipv4_addr, "-w"}) !=
      0) {
    success = false;
  }

  if (!success) {
    LOG(ERROR) << "Failed to configure ingress DNAT rules on " << ifname
               << " to " << ipv4_addr;
    RemoveInboundIPv4DNAT(ifname, ipv4_addr);
  }
}

void Datapath::RemoveInboundIPv4DNAT(const std::string& ifname,
                                     const std::string& ipv4_addr) {
  process_runner_->iptables(
      "nat", {"-D", kIngressDefaultForwardingChain, "-i", ifname, "-p", "udp",
              "-j", "DNAT", "--to-destination", ipv4_addr, "-w"});
  process_runner_->iptables(
      "nat", {"-D", kIngressDefaultForwardingChain, "-i", ifname, "-p", "tcp",
              "-j", "DNAT", "--to-destination", ipv4_addr, "-w"});
  process_runner_->iptables(
      "nat", {"-D", kIngressDefaultForwardingChain, "-i", ifname, "-m",
              "socket", "--nowildcard", "-j", "ACCEPT", "-w"});
}

bool Datapath::AddRedirectDnsRule(const std::string& ifname,
                                  const std::string dns_ipv4_addr) {
  bool success = true;
  success &= RemoveRedirectDnsRule(ifname);
  // Use Insert operation to ensure that the new DNS address is used first.
  success &= ModifyRedirectDnsDNATRule("-I", "tcp", ifname, dns_ipv4_addr);
  success &= ModifyRedirectDnsDNATRule("-I", "udp", ifname, dns_ipv4_addr);
  physical_dns_addresses_[ifname] = dns_ipv4_addr;
  return success;
}

bool Datapath::RemoveRedirectDnsRule(const std::string& ifname) {
  const auto it = physical_dns_addresses_.find(ifname);
  if (it == physical_dns_addresses_.end())
    return true;

  bool success = true;
  success &= ModifyRedirectDnsDNATRule("-D", "tcp", ifname, it->second);
  success &= ModifyRedirectDnsDNATRule("-D", "udp", ifname, it->second);
  physical_dns_addresses_.erase(it);
  return success;
}

bool Datapath::ModifyRedirectDnsDNATRule(const std::string& op,
                                         const std::string& protocol,
                                         const std::string& ifname,
                                         const std::string& dns_ipv4_addr) {
  std::vector<std::string> args = {op,
                                   kRedirectDnsChain,
                                   "-p",
                                   protocol,
                                   "--dport",
                                   "53",
                                   "-o",
                                   ifname,
                                   "-j",
                                   "DNAT",
                                   "--to-destination",
                                   dns_ipv4_addr,
                                   "-w"};
  return ModifyIptables(IpFamily::IPv4, "nat", args);
}

bool Datapath::ModifyRedirectDnsJumpRule(IpFamily family,
                                         const std::string& op,
                                         const std::string& chain,
                                         const std::string& ifname,
                                         const std::string& target_chain,
                                         Fwmark mark,
                                         Fwmark mask,
                                         bool redirect_on_mark) {
  std::vector<std::string> args = {op, chain};
  if (!ifname.empty()) {
    args.insert(args.end(), {"-i", ifname});
  }
  if (mark.Value() != 0 && mask.Value() != 0) {
    args.insert(args.end(), {"-m", "mark"});
    if (!redirect_on_mark) {
      args.push_back("!");
    }
    args.insert(args.end(),
                {"--mark", mark.ToString() + "/" + mask.ToString()});
  }
  args.insert(args.end(), {"-j", target_chain, "-w"});
  return ModifyIptables(family, "nat", args);
}

bool Datapath::ModifyDnsRedirectionSkipVpnRule(IpFamily family,
                                               const std::string& op) {
  bool success = true;
  for (const auto& protocol : {"udp", "tcp"}) {
    std::vector<std::string> args = {op, kSkipApplyVpnMarkChain};
    args.push_back("-p");
    args.push_back(protocol);
    args.push_back("--dport");
    args.push_back(kDefaultDnsPort);
    args.push_back("-j");
    args.push_back("ACCEPT");
    args.push_back("-w");
    if (!ModifyIptables(family, "mangle", args)) {
      success = false;
    }
  }
  return success;
}

bool Datapath::MaskInterfaceFlags(const std::string& ifname,
                                  uint16_t on,
                                  uint16_t off) {
  base::ScopedFD sock(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (!sock.is_valid()) {
    PLOG(ERROR) << "Failed to create control socket";
    return false;
  }
  ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());
  if (system_->Ioctl(sock.get(), SIOCGIFFLAGS, &ifr) < 0) {
    PLOG(WARNING) << "ioctl() failed to get interface flag on " << ifname;
    return false;
  }
  ifr.ifr_flags |= on;
  ifr.ifr_flags &= ~off;
  if (system_->Ioctl(sock.get(), SIOCSIFFLAGS, &ifr) < 0) {
    PLOG(WARNING) << "ioctl() failed to set flag 0x" << std::hex << on
                  << " unset flag 0x" << std::hex << off << " on " << ifname;
    return false;
  }
  return true;
}

bool Datapath::AddIPv6HostRoute(const std::string& ifname,
                                const std::string& ipv6_addr,
                                int ipv6_prefix_len) {
  std::string ipv6_addr_cidr =
      ipv6_addr + "/" + std::to_string(ipv6_prefix_len);

  return process_runner_->ip6("route", "replace",
                              {ipv6_addr_cidr, "dev", ifname}) == 0;
}

void Datapath::RemoveIPv6HostRoute(const std::string& ifname,
                                   const std::string& ipv6_addr,
                                   int ipv6_prefix_len) {
  std::string ipv6_addr_cidr =
      ipv6_addr + "/" + std::to_string(ipv6_prefix_len);

  process_runner_->ip6("route", "del", {ipv6_addr_cidr, "dev", ifname});
}

bool Datapath::AddIPv6Address(const std::string& ifname,
                              const std::string& ipv6_addr) {
  return process_runner_->ip6("addr", "add", {ipv6_addr, "dev", ifname}) == 0;
}

void Datapath::RemoveIPv6Address(const std::string& ifname,
                                 const std::string& ipv6_addr) {
  process_runner_->ip6("addr", "del", {ipv6_addr, "dev", ifname});
}

void Datapath::StartConnectionPinning(const std::string& ext_ifname) {
  int ifindex = system_->IfNametoindex(ext_ifname);
  if (ifindex == 0) {
    // Can happen if the interface has already been removed (b/183679000).
    LOG(ERROR) << "Failed to set up connection pinning on " << ext_ifname;
    return;
  }

  std::string subchain = "POSTROUTING_" + ext_ifname;
  // This can fail if patchpanel did not stopped correctly or failed to cleanup
  // the chain when |ext_ifname| was previously deleted.
  if (!AddChain(IpFamily::Dual, "mangle", subchain)) {
    LOG(ERROR) << "Failed to create mangle chain " << subchain;
  }
  // Make sure the chain is empty if patchpanel did not cleaned correctly that
  // chain before.
  if (!FlushChain(IpFamily::Dual, "mangle", subchain)) {
    LOG(ERROR) << "Could not flush " << subchain;
  }
  if (!ModifyJumpRule(IpFamily::Dual, "mangle", "-A", "POSTROUTING", subchain,
                      "" /*iif*/, ext_ifname)) {
    LOG(ERROR) << "Could not add jump rule from mangle POSTROUTING to "
               << subchain;
  }

  Fwmark routing_mark = Fwmark::FromIfIndex(ifindex);
  LOG(INFO) << "Start connection pinning on " << ext_ifname
            << " fwmark=" << routing_mark.ToString();
  // Set in CONNMARK the routing tag associated with |ext_ifname|.
  if (!ModifyConnmarkSet(IpFamily::Dual, subchain, "-A", routing_mark,
                         kFwmarkRoutingMask)) {
    LOG(ERROR) << "Could not start connection pinning on " << ext_ifname;
  }
  // Save in CONNMARK the source tag for egress traffic of this connection.
  if (!ModifyConnmarkSave(IpFamily::Dual, subchain, "-A",
                          kFwmarkAllSourcesMask)) {
    LOG(ERROR) << "Failed to add POSTROUTING CONNMARK rule for saving fwmark "
                  "source tag on "
               << ext_ifname;
  }
  // Restore from CONNMARK the source tag for ingress traffic of this connection
  // (returned traffic).
  if (!ModifyConnmarkRestore(IpFamily::Dual, "PREROUTING", "-A", ext_ifname,
                             kFwmarkAllSourcesMask)) {
    LOG(ERROR) << "Could not setup fwmark source tagging rule for return "
                  "traffic received on "
               << ext_ifname;
  }
}

void Datapath::StopConnectionPinning(const std::string& ext_ifname) {
  std::string subchain = "POSTROUTING_" + ext_ifname;
  ModifyJumpRule(IpFamily::Dual, "mangle", "-D", "POSTROUTING", subchain,
                 "" /*iif*/, ext_ifname);
  FlushChain(IpFamily::Dual, "mangle", subchain);
  RemoveChain(IpFamily::Dual, "mangle", subchain);
  if (!ModifyConnmarkRestore(IpFamily::Dual, "PREROUTING", "-D", ext_ifname,
                             kFwmarkAllSourcesMask)) {
    LOG(ERROR) << "Could not remove fwmark source tagging rule for return "
                  "traffic received on "
               << ext_ifname;
  }
}

void Datapath::StartVpnRouting(const std::string& vpn_ifname) {
  int ifindex = system_->IfNametoindex(vpn_ifname);
  if (ifindex == 0) {
    // Can happen if the interface has already been removed (b/183679000).
    LOG(ERROR) << "Failed to start VPN routing on " << vpn_ifname;
    return;
  }

  Fwmark routing_mark = Fwmark::FromIfIndex(ifindex);
  LOG(INFO) << "Start VPN routing on " << vpn_ifname
            << " fwmark=" << routing_mark.ToString();
  if (!ModifyJumpRule(IpFamily::IPv4, "nat", "-A", "POSTROUTING", "MASQUERADE",
                      "" /*iif*/, vpn_ifname)) {
    LOG(ERROR) << "Could not set up SNAT for traffic outgoing " << vpn_ifname;
  }
  StartConnectionPinning(vpn_ifname);

  // Any traffic that already has a routing tag applied is accepted.
  if (!ModifyIptables(
          IpFamily::Dual, "mangle",
          {"-A", kApplyVpnMarkChain, "-m", "mark", "!", "--mark",
           "0x0/" + kFwmarkRoutingMask.ToString(), "-j", "ACCEPT", "-w"})) {
    LOG(ERROR) << "Failed to add ACCEPT rule to VPN tagging chain for marked "
                  "connections";
  }
  // Otherwise, any new traffic from a new connection gets marked with the
  // VPN routing tag.
  if (!ModifyFwmarkRoutingTag(kApplyVpnMarkChain, "-A", routing_mark))
    LOG(ERROR) << "Failed to set up VPN set-mark rule for " << vpn_ifname;

  // When the VPN client runs on the host, also route arcbr0 to that VPN so
  // that ARC can access the VPN network through arc0.
  if (vpn_ifname != kArcBridge) {
    StartRoutingDevice(vpn_ifname, kArcBridge, 0 /*no inbound DNAT */,
                       TrafficSource::ARC, true /* route_on_vpn */);
  }
  if (!ModifyRedirectDnsJumpRule(
          IpFamily::IPv4, "-A", "OUTPUT", "" /* ifname */, kRedirectDnsChain,
          kFwmarkRouteOnVpn, kFwmarkVpnMask, false /* redirect_on_mark */)) {
    LOG(ERROR) << "Failed to set jump rule to " << kRedirectDnsChain;
  }

  // All traffic with the VPN routing tag are explicitly accepted in the filter
  // table. This prevents the VPN lockdown chain to reject that traffic when VPN
  // lockdown is enabled.
  if (!ModifyIptables(
          IpFamily::Dual, "filter",
          {"-A", kVpnAcceptChain, "-m", "mark", "--mark",
           routing_mark.ToString() + "/" + kFwmarkRoutingMask.ToString(), "-j",
           "ACCEPT", "-w"})) {
    LOG(ERROR) << "Failed to set filter rule for accepting VPN marked traffic";
  }
}

void Datapath::StopVpnRouting(const std::string& vpn_ifname) {
  LOG(INFO) << "Stop VPN routing on " << vpn_ifname;
  if (!FlushChain(IpFamily::Dual, "filter", kVpnAcceptChain)) {
    LOG(ERROR) << "Could not flush " << kVpnAcceptChain;
  }
  if (vpn_ifname != kArcBridge) {
    StopRoutingDevice(vpn_ifname, kArcBridge, 0 /* no inbound DNAT */,
                      TrafficSource::ARC, false /* route_on_vpn */);
  }
  if (!FlushChain(IpFamily::Dual, "mangle", kApplyVpnMarkChain)) {
    LOG(ERROR) << "Could not flush " << kApplyVpnMarkChain;
  }
  StopConnectionPinning(vpn_ifname);
  if (!ModifyJumpRule(IpFamily::IPv4, "nat", "-D", "POSTROUTING", "MASQUERADE",
                      "" /*iif*/, vpn_ifname)) {
    LOG(ERROR) << "Could not stop SNAT for traffic outgoing " << vpn_ifname;
  }
  if (!ModifyRedirectDnsJumpRule(
          IpFamily::IPv4, "-D", "OUTPUT", "" /* ifname */, kRedirectDnsChain,
          kFwmarkRouteOnVpn, kFwmarkVpnMask, false /* redirect_on_mark */)) {
    LOG(ERROR) << "Failed to remove jump rule to " << kRedirectDnsChain;
  }
}

void Datapath::SetVpnLockdown(bool enable_vpn_lockdown) {
  if (enable_vpn_lockdown) {
    if (!ModifyIptables(
            IpFamily::Dual, "filter",
            {"-A", kVpnLockdownChain, "-m", "mark", "--mark",
             kFwmarkRouteOnVpn.ToString() + "/" + kFwmarkVpnMask.ToString(),
             "-j", "REJECT", "-w"})) {
      LOG(ERROR) << "Failed to start VPN lockdown mode";
    }
  } else {
    if (!FlushChain(IpFamily::Dual, "filter", kVpnLockdownChain)) {
      LOG(ERROR) << "Failed to stop VPN lockdown mode";
    }
  }
}

bool Datapath::ModifyConnmarkSet(IpFamily family,
                                 const std::string& chain,
                                 const std::string& op,
                                 Fwmark mark,
                                 Fwmark mask) {
  return ModifyIptables(family, "mangle",
                        {op, chain, "-j", "CONNMARK", "--set-mark",
                         mark.ToString() + "/" + mask.ToString(), "-w"});
}

bool Datapath::ModifyConnmarkRestore(IpFamily family,
                                     const std::string& chain,
                                     const std::string& op,
                                     const std::string& iif,
                                     Fwmark mask) {
  std::vector<std::string> args = {op, chain};
  if (!iif.empty()) {
    args.push_back("-i");
    args.push_back(iif);
  }
  args.insert(args.end(), {"-j", "CONNMARK", "--restore-mark", "--mask",
                           mask.ToString(), "-w"});
  return ModifyIptables(family, "mangle", args);
}

bool Datapath::ModifyConnmarkSave(IpFamily family,
                                  const std::string& chain,
                                  const std::string& op,
                                  Fwmark mask) {
  std::vector<std::string> args = {
      op,       chain,           "-j", "CONNMARK", "--save-mark",
      "--mask", mask.ToString(), "-w"};
  return ModifyIptables(family, "mangle", args);
}

bool Datapath::ModifyFwmarkRoutingTag(const std::string& chain,
                                      const std::string& op,
                                      Fwmark routing_mark) {
  return ModifyFwmark(IpFamily::Dual, chain, op, "" /*int_ifname*/,
                      "" /*uid_name*/, 0 /*classid*/, routing_mark,
                      kFwmarkRoutingMask);
}

bool Datapath::ModifyFwmarkSourceTag(const std::string& chain,
                                     const std::string& op,
                                     TrafficSource source) {
  return ModifyFwmark(IpFamily::Dual, chain, op, "" /*iif*/, "" /*uid_name*/,
                      0 /*classid*/, Fwmark::FromSource(source),
                      kFwmarkAllSourcesMask);
}

bool Datapath::ModifyFwmarkDefaultLocalSourceTag(const std::string& op,
                                                 TrafficSource source) {
  std::vector<std::string> args = {"-A",
                                   kApplyLocalSourceMarkChain,
                                   "-m",
                                   "mark",
                                   "--mark",
                                   "0x0/" + kFwmarkAllSourcesMask.ToString(),
                                   "-j",
                                   "MARK",
                                   "--set-mark",
                                   Fwmark::FromSource(source).ToString() + "/" +
                                       kFwmarkAllSourcesMask.ToString(),
                                   "-w"};
  return ModifyIptables(IpFamily::Dual, "mangle", args);
}

bool Datapath::ModifyFwmarkLocalSourceTag(const std::string& op,
                                          const LocalSourceSpecs& source) {
  if (std::string(source.uid_name).empty() && source.classid == 0)
    return false;

  Fwmark mark = Fwmark::FromSource(source.source_type);
  if (source.is_on_vpn)
    mark = mark | kFwmarkRouteOnVpn;

  return ModifyFwmark(IpFamily::Dual, kApplyLocalSourceMarkChain, op,
                      "" /*iif*/, source.uid_name, source.classid, mark,
                      kFwmarkPolicyMask);
}

bool Datapath::ModifyFwmark(IpFamily family,
                            const std::string& chain,
                            const std::string& op,
                            const std::string& iif,
                            const std::string& uid_name,
                            uint32_t classid,
                            Fwmark mark,
                            Fwmark mask,
                            bool log_failures) {
  std::vector<std::string> args = {op, chain};
  if (!iif.empty()) {
    args.push_back("-i");
    args.push_back(iif);
  }
  if (!uid_name.empty()) {
    args.push_back("-m");
    args.push_back("owner");
    args.push_back("--uid-owner");
    args.push_back(uid_name);
  }
  if (classid != 0) {
    args.push_back("-m");
    args.push_back("cgroup");
    args.push_back("--cgroup");
    args.push_back(base::StringPrintf("0x%08x", classid));
  }
  args.push_back("-j");
  args.push_back("MARK");
  args.push_back("--set-mark");
  args.push_back(mark.ToString() + "/" + mask.ToString());
  args.push_back("-w");

  return ModifyIptables(family, "mangle", args, log_failures);
}

bool Datapath::ModifyJumpRule(IpFamily family,
                              const std::string& table,
                              const std::string& op,
                              const std::string& chain,
                              const std::string& target,
                              const std::string& iif,
                              const std::string& oif,
                              bool log_failures) {
  std::vector<std::string> args = {op, chain};
  if (!iif.empty()) {
    args.push_back("-i");
    args.push_back(iif);
  }
  if (!oif.empty()) {
    args.push_back("-o");
    args.push_back(oif);
  }
  args.insert(args.end(), {"-j", target, "-w"});
  return ModifyIptables(family, table, args, log_failures);
}

bool Datapath::ModifyFwmarkVpnJumpRule(const std::string& chain,
                                       const std::string& op,
                                       Fwmark mark,
                                       Fwmark mask) {
  std::vector<std::string> args = {op, chain};
  if (mark.Value() != 0 && mask.Value() != 0) {
    args.push_back("-m");
    args.push_back("mark");
    args.push_back("--mark");
    args.push_back(mark.ToString() + "/" + mask.ToString());
  }
  args.insert(args.end(), {"-j", kApplyVpnMarkChain, "-w"});
  return ModifyIptables(IpFamily::Dual, "mangle", args);
}

bool Datapath::ModifyFwmarkSkipVpnJumpRule(const std::string& chain,
                                           const std::string& op,
                                           const std::string& uid,
                                           bool log_failures) {
  std::vector<std::string> args = {op, chain};
  if (!uid.empty()) {
    args.push_back("-m");
    args.push_back("owner");
    args.push_back("!");
    args.push_back("--uid-owner");
    args.push_back(uid);
  }
  args.insert(args.end(), {"-j", kSkipApplyVpnMarkChain, "-w"});
  return ModifyIptables(IpFamily::Dual, "mangle", args, log_failures);
}

bool Datapath::AddChain(IpFamily family,
                        const std::string& table,
                        const std::string& name) {
  DCHECK(name.size() <= kIptablesMaxChainLength);
  return ModifyChain(family, table, "-N", name);
}

bool Datapath::RemoveChain(IpFamily family,
                           const std::string& table,
                           const std::string& name) {
  return ModifyChain(family, table, "-X", name);
}

bool Datapath::FlushChain(IpFamily family,
                          const std::string& table,
                          const std::string& name) {
  return ModifyChain(family, table, "-F", name);
}

bool Datapath::ModifyChain(IpFamily family,
                           const std::string& table,
                           const std::string& op,
                           const std::string& chain,
                           bool log_failures) {
  return ModifyIptables(family, table, {op, chain, "-w"}, log_failures);
}

bool Datapath::ModifyIptables(IpFamily family,
                              const std::string& table,
                              const std::vector<std::string>& argv,
                              bool log_failures) {
  switch (family) {
    case IPv4:
    case IPv6:
    case Dual:
      break;
    default:
      LOG(ERROR) << "Could not execute iptables command " << table
                 << base::JoinString(argv, " ") << ": incorrect IP family "
                 << family;
      return false;
  }

  bool success = true;
  if (family & IpFamily::IPv4) {
    success &= process_runner_->iptables(table, argv, log_failures) == 0;
  }
  if (family & IpFamily::IPv6) {
    success &= process_runner_->ip6tables(table, argv, log_failures) == 0;
  }
  return success;
}

std::string Datapath::DumpIptables(IpFamily family, const std::string& table) {
  std::string result;
  std::vector<std::string> argv = {"-L", "-x", "-v", "-n", "-w"};
  switch (family) {
    case IPv4:
      if (process_runner_->iptables(table, argv, true /*log_failures*/,
                                    &result) != 0) {
        LOG(ERROR) << "Could not dump iptables " << table;
      }
      break;
    case IPv6:
      if (process_runner_->ip6tables(table, argv, true /*log_failures*/,
                                     &result) != 0) {
        LOG(ERROR) << "Could not dump ip6tables " << table;
      }
      break;
    case Dual:
      LOG(ERROR) << "Cannot dump iptables and ip6tables at the same time";
      break;
    default:
      LOG(ERROR) << "Could not dump iptables: incorrect IP family " << family;
  }
  return result;
}

bool Datapath::AddIPv4Route(uint32_t gateway_addr,
                            uint32_t addr,
                            uint32_t netmask) {
  struct rtentry route;
  memset(&route, 0, sizeof(route));
  SetSockaddrIn(&route.rt_gateway, gateway_addr);
  SetSockaddrIn(&route.rt_dst, addr & netmask);
  SetSockaddrIn(&route.rt_genmask, netmask);
  route.rt_flags = RTF_UP | RTF_GATEWAY;
  return ModifyRtentry(SIOCADDRT, &route);
}

bool Datapath::DeleteIPv4Route(uint32_t gateway_addr,
                               uint32_t addr,
                               uint32_t netmask) {
  struct rtentry route;
  memset(&route, 0, sizeof(route));
  SetSockaddrIn(&route.rt_gateway, gateway_addr);
  SetSockaddrIn(&route.rt_dst, addr & netmask);
  SetSockaddrIn(&route.rt_genmask, netmask);
  route.rt_flags = RTF_UP | RTF_GATEWAY;
  return ModifyRtentry(SIOCDELRT, &route);
}

bool Datapath::AddIPv4Route(const std::string& ifname,
                            uint32_t addr,
                            uint32_t netmask) {
  struct rtentry route;
  memset(&route, 0, sizeof(route));
  SetSockaddrIn(&route.rt_dst, addr & netmask);
  SetSockaddrIn(&route.rt_genmask, netmask);
  char rt_dev[IFNAMSIZ];
  strncpy(rt_dev, ifname.c_str(), IFNAMSIZ);
  rt_dev[IFNAMSIZ - 1] = '\0';
  route.rt_dev = rt_dev;
  route.rt_flags = RTF_UP | RTF_GATEWAY;
  return ModifyRtentry(SIOCADDRT, &route);
}

bool Datapath::DeleteIPv4Route(const std::string& ifname,
                               uint32_t addr,
                               uint32_t netmask) {
  struct rtentry route;
  memset(&route, 0, sizeof(route));
  SetSockaddrIn(&route.rt_dst, addr & netmask);
  SetSockaddrIn(&route.rt_genmask, netmask);
  char rt_dev[IFNAMSIZ];
  strncpy(rt_dev, ifname.c_str(), IFNAMSIZ);
  rt_dev[IFNAMSIZ - 1] = '\0';
  route.rt_dev = rt_dev;
  route.rt_flags = RTF_UP | RTF_GATEWAY;
  return ModifyRtentry(SIOCDELRT, &route);
}

bool Datapath::ModifyRtentry(ioctl_req_t op, struct rtentry* route) {
  DCHECK(route);
  if (op != SIOCADDRT && op != SIOCDELRT) {
    LOG(ERROR) << "Invalid operation " << op << " for rtentry " << *route;
    return false;
  }
  base::ScopedFD fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to create socket for adding rtentry " << *route;
    return false;
  }
  if (HANDLE_EINTR(system_->Ioctl(fd.get(), op, route)) != 0) {
    // b/190119762: Ignore "No such process" errors when deleting a struct
    // rtentry if some other prior or concurrent operation already resulted in
    // this route being deleted.
    if (op == SIOCDELRT && errno == ESRCH) {
      return true;
    }
    std::string opname = op == SIOCADDRT ? "add" : "delete";
    PLOG(ERROR) << "Failed to " << opname << " rtentry " << *route;
    return false;
  }
  return true;
}

bool Datapath::AddAdbPortForwardRule(const std::string& ifname) {
  return firewall_->AddIpv4ForwardRule(patchpanel::ModifyPortRuleRequest::TCP,
                                       kArcAddr, kAdbServerPort, ifname,
                                       kLocalhostAddr, kAdbProxyTcpListenPort);
}

void Datapath::DeleteAdbPortForwardRule(const std::string& ifname) {
  firewall_->DeleteIpv4ForwardRule(patchpanel::ModifyPortRuleRequest::TCP,
                                   kArcAddr, kAdbServerPort, ifname,
                                   kLocalhostAddr, kAdbProxyTcpListenPort);
}

bool Datapath::AddAdbPortAccessRule(const std::string& ifname) {
  return firewall_->AddAcceptRules(patchpanel::ModifyPortRuleRequest::TCP,
                                   kAdbProxyTcpListenPort, ifname);
}

void Datapath::DeleteAdbPortAccessRule(const std::string& ifname) {
  firewall_->DeleteAcceptRules(patchpanel::ModifyPortRuleRequest::TCP,
                               kAdbProxyTcpListenPort, ifname);
}

bool Datapath::SetConntrackHelpers(const bool enable_helpers) {
  return system_->SysNetSet(System::SysNet::ConntrackHelper,
                            enable_helpers ? "1" : "0");
}

bool Datapath::SetRouteLocalnet(const std::string& ifname, const bool enable) {
  return system_->SysNetSet(System::SysNet::IPv4RouteLocalnet,
                            enable ? "1" : "0", ifname);
}

bool Datapath::ModprobeAll(const std::vector<std::string>& modules) {
  return process_runner_->modprobe_all(modules) == 0;
}

bool Datapath::ModifyPortRule(
    const patchpanel::ModifyPortRuleRequest& request) {
  switch (request.proto()) {
    case patchpanel::ModifyPortRuleRequest::TCP:
    case patchpanel::ModifyPortRuleRequest::UDP:
      break;
    default:
      LOG(ERROR) << "Unknown protocol " << request.proto();
      return false;
  }

  switch (request.op()) {
    case patchpanel::ModifyPortRuleRequest::CREATE:
      switch (request.type()) {
        case patchpanel::ModifyPortRuleRequest::ACCESS: {
          return firewall_->AddAcceptRules(request.proto(),
                                           request.input_dst_port(),
                                           request.input_ifname());
        }
        case patchpanel::ModifyPortRuleRequest::LOCKDOWN:
          return firewall_->AddLoopbackLockdownRules(request.proto(),
                                                     request.input_dst_port());
        case patchpanel::ModifyPortRuleRequest::FORWARDING:
          return firewall_->AddIpv4ForwardRule(
              request.proto(), request.input_dst_ip(), request.input_dst_port(),
              request.input_ifname(), request.dst_ip(), request.dst_port());
        default:
          LOG(ERROR) << "Unknown port rule type " << request.type();
          return false;
      }
    case patchpanel::ModifyPortRuleRequest::DELETE:
      switch (request.type()) {
        case patchpanel::ModifyPortRuleRequest::ACCESS:
          return firewall_->DeleteAcceptRules(request.proto(),
                                              request.input_dst_port(),
                                              request.input_ifname());
        case patchpanel::ModifyPortRuleRequest::LOCKDOWN:
          return firewall_->DeleteLoopbackLockdownRules(
              request.proto(), request.input_dst_port());
        case patchpanel::ModifyPortRuleRequest::FORWARDING:
          return firewall_->DeleteIpv4ForwardRule(
              request.proto(), request.input_dst_ip(), request.input_dst_port(),
              request.input_ifname(), request.dst_ip(), request.dst_port());
        default:
          LOG(ERROR) << "Unknown port rule type " << request.type();
          return false;
      }
    default:
      LOG(ERROR) << "Unknown operation " << request.op();
      return false;
  }
}

std::ostream& operator<<(std::ostream& stream,
                         const ConnectedNamespace& nsinfo) {
  stream << "{ pid: " << nsinfo.pid
         << ", source: " << TrafficSourceName(nsinfo.source);
  if (!nsinfo.outbound_ifname.empty()) {
    stream << ", outbound_ifname: " << nsinfo.outbound_ifname;
  }
  stream << ", route_on_vpn: " << nsinfo.route_on_vpn
         << ", host_ifname: " << nsinfo.host_ifname
         << ", peer_ifname: " << nsinfo.peer_ifname
         << ", peer_subnet: " << nsinfo.peer_subnet->ToCidrString() << '}';
  return stream;
}

std::ostream& operator<<(std::ostream& stream, const DnsRedirectionRule& rule) {
  stream << "{ type: "
         << SetDnsRedirectionRuleRequest::RuleType_Name(rule.type);
  if (!rule.input_ifname.empty()) {
    stream << ", input_ifname: " << rule.input_ifname;
  }
  if (!rule.proxy_address.empty()) {
    stream << ", proxy_address: " << rule.proxy_address;
  }
  if (!rule.nameservers.empty()) {
    stream << ", nameserver(s): " << base::JoinString(rule.nameservers, ",");
  }
  stream << " }";
  return stream;
}

}  // namespace patchpanel
