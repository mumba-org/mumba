// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DATAPATH_H_
#define PATCHPANEL_DATAPATH_H_

#include <net/route.h>
#include <sys/types.h>

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "patchpanel/firewall.h"
#include "patchpanel/mac_address_generator.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/net_util.h"
#include "patchpanel/routing_service.h"
#include "patchpanel/scoped_ns.h"
#include "patchpanel/subnet.h"
#include "patchpanel/system.h"

namespace patchpanel {

// filter INPUT chain for ingress port access rules controlled by
// permission_broker.
constexpr char kIngressPortFirewallChain[] = "ingress_port_firewall";
// filter OUTPUT chain for egress port restriction rules controlled by
// permission_broker.
constexpr char kEgressPortFirewallChain[] = "egress_port_firewall";
// nat PREROUTING chain for ingress DNAT forwarding rules controlled by
// permission_broker.
constexpr char kIngressPortForwardingChain[] = "ingress_port_forwarding";

// Struct holding parameters for Datapath::StartRoutingNamespace requests.
struct ConnectedNamespace {
  // The special pid which indicates this namespace is not attached to an
  // associated process but should be/was created by `ip netns add`.
  static constexpr pid_t kNewNetnsPid = -1;

  // The pid of the client network namespace.
  pid_t pid;
  // The name attached to the client network namespace.
  std::string netns_name;
  // Source to which traffic from |host_ifname| will be attributed.
  TrafficSource source;
  // Interface name of the shill Device for routing outbound traffic from the
  // client namespace. Empty if outbound traffic should be forwarded to the
  // highest priority network (physical or virtual).
  std::string outbound_ifname;
  // If |outbound_ifname| is empty and |route_on_vpn| is false, the traffic from
  // the client namespace will be routed to the highest priority physical
  // network. If |outbound_ifname| is empty and |route_on_vpn| is true, the
  // traffic will be routed through VPN connections. If |outbound_ifname|
  // specifies a valid physical interface, |route_on_vpn| is ignored.
  bool route_on_vpn;
  // Name of the "local" veth interface visible on the host namespace.
  std::string host_ifname;
  // Name of the "remote" veth interface moved into the client namespace.
  std::string peer_ifname;
  // IPv4 subnet assigned to the client namespace.
  std::unique_ptr<Subnet> peer_subnet;
  // MAC address of the "local" veth interface visible on the host namespace.
  MacAddress host_mac_addr;
  // MAC address of the "remote" veth interface.
  MacAddress peer_mac_addr;
  // Interface name of the shill device for routing outbound traffic from the
  // client namespace. This will be filled to keep track of the upstream
  // interface if |outbound_ifname| is empty.
  std::string tracked_outbound_ifname;
};

struct DnsRedirectionRule {
  patchpanel::SetDnsRedirectionRuleRequest::RuleType type;
  std::string input_ifname;
  std::string proxy_address;
  std::vector<std::string> nameservers;
};

std::ostream& operator<<(std::ostream& stream,
                         const ConnectedNamespace& nsinfo);

std::ostream& operator<<(std::ostream& stream, const DnsRedirectionRule& rule);

// Simple enum of bitmasks used for specifying a set of IP family values.
enum IpFamily {
  NONE = 0,
  IPv4 = 1 << 0,
  IPv6 = 1 << 1,
  Dual = IPv4 | IPv6,  // (1 << 0) | (1 << 1);
};

// Returns for given interface name the host name of a ARC veth pair.
std::string ArcVethHostName(const std::string& ifname);

// Returns the ARC bridge interface name for the given interface.
std::string ArcBridgeName(const std::string& ifname);

// ARC networking data path configuration utility.
// IPV4 addresses are always specified in singular dotted-form (a.b.c.d)
// (not in CIDR representation
class Datapath {
 public:
  explicit Datapath(System* system);
  // Provided for testing only.
  Datapath(MinijailedProcessRunner* process_runner,
           Firewall* firewall,
           System* system);
  Datapath(const Datapath&) = delete;
  Datapath& operator=(const Datapath&) = delete;

  virtual ~Datapath() = default;

  // Start and stop the Datapath, creating or destroying the initial iptables
  // setup needed for forwarding traffic from VMs and containers and for
  // fwmark based routing.
  virtual void Start();
  virtual void Stop();

  // Attaches the name |netns_name| to a network namespace identified by
  // |netns_pid|. If |netns_pid| is -1, a new namespace with name |netns_name|
  // will be created instead. If |netns_name| had already been created, it will
  // be deleted first.
  virtual bool NetnsAttachName(const std::string& netns_name, pid_t netns_pid);

  // Deletes the name |netns_name| of a network namespace.
  virtual bool NetnsDeleteName(const std::string& netns_name);

  virtual bool AddBridge(const std::string& ifname,
                         uint32_t ipv4_addr,
                         uint32_t ipv4_prefix_len);
  virtual void RemoveBridge(const std::string& ifname);

  virtual bool AddToBridge(const std::string& br_ifname,
                           const std::string& ifname);

  // Adds a new TAP device.
  // |name| may be empty, in which case a default device name will be used;
  // it may be a template (e.g. vmtap%d), in which case the kernel will
  // generate the name; or it may be fully defined. In all cases, upon success,
  // the function returns the actual name of the interface.
  // |mac_addr| and |ipv4_addr| should be null if this interface will be later
  // bridged.
  // If |user| is empty, no owner will be set
  virtual std::string AddTAP(const std::string& name,
                             const MacAddress* mac_addr,
                             const SubnetAddress* ipv4_addr,
                             const std::string& user);

  // |ifname| must be the actual name of the interface.
  virtual void RemoveTAP(const std::string& ifname);

  // The following are iptables methods.
  // When specified, |ipv4_addr| is always singlar dotted-form (a.b.c.d)
  // IPv4 address (not a CIDR representation).

  // Creates a virtual interface pair split across the current namespace and the
  // namespace corresponding to |pid|, and set up the remote interface
  // |peer_ifname| according // to the given parameters.
  virtual bool ConnectVethPair(pid_t pid,
                               const std::string& netns_name,
                               const std::string& veth_ifname,
                               const std::string& peer_ifname,
                               const MacAddress& remote_mac_addr,
                               uint32_t remote_ipv4_addr,
                               uint32_t remote_ipv4_prefix_len,
                               bool remote_multicast_flag);

  // Disable and re-enable IPv6.
  virtual void RestartIPv6();

  virtual void RemoveInterface(const std::string& ifname);

  // Create an OUTPUT DROP rule for any locally originated traffic
  // whose src IPv4 matches |src_ip| and would exit |oif|. This is mainly used
  // for dropping Chrome webRTC traffic incorrectly bound on ARC and other
  // guests virtual interfaces (chromium:898210).
  virtual bool AddSourceIPv4DropRule(const std::string& oif,
                                     const std::string& src_ip);

  // Creates a virtual ethernet interface pair shared with the client namespace
  // of |nsinfo.pid| and sets up routing outside and inside the client namespace
  // for connecting the client namespace to the network.
  bool StartRoutingNamespace(const ConnectedNamespace& nsinfo);
  // Destroys the virtual ethernet interface, routing, and network namespace
  // name set for |nsinfo.netns_name| by StartRoutingNamespace. The default
  // route set inside the |nsinfo.netns_name| by patchpanel is not destroyed and
  // it is assumed the client will teardown the namespace.
  void StopRoutingNamespace(const ConnectedNamespace& nsinfo);

  // Start or stop DNS traffic redirection to DNS proxy. The rules created
  // depend on the type requested.
  bool StartDnsRedirection(const DnsRedirectionRule& rule);
  void StopDnsRedirection(const DnsRedirectionRule& rule);

  // Sets up IPv4 SNAT, IP forwarding, and traffic marking for the given
  // downstream network interface |int_ifname| associated to |source|. if
  // |ext_ifname| is empty, traffic from the downstream interface is implicitly
  // routed through the highest priority physical network when |route_on_vpn| is
  // false, or through the highest priority logical network when |route_on_vpn|
  // is true. If |ext_ifname| is defined, traffic from the downstream interface
  // is routed to |ext_ifname| and |route_on_vpn| is ignored. If |int_ifname| is
  // associated to a connected namespace and a VPN is connected, an additional
  // IPv4 VPN fwmark tagging bypass rule is needed to allow return traffic to
  // reach to the IPv4 local source. |peer_ipv4_addr| is the address of the
  // interface inside the connected namespace needed to create this rule. If
  // |peer_ipv4_addr| is 0, no additional rule will be added.
  virtual void StartRoutingDevice(const std::string& ext_ifname,
                                  const std::string& int_ifname,
                                  uint32_t int_ipv4_addr,
                                  TrafficSource source,
                                  bool route_on_vpn,
                                  uint32_t peer_ipv4_addr = 0);

  // Removes IPv4 iptables, IP forwarding, and traffic marking for the given
  // downstream network interface |int_ifname|.
  virtual void StopRoutingDevice(const std::string& ext_ifname,
                                 const std::string& int_ifname,
                                 uint32_t int_ipv4_addr,
                                 TrafficSource source,
                                 bool route_on_vpn);

  // Starts or stops marking conntrack entries routed to |ext_ifname| with its
  // associated fwmark routing tag. Once a conntrack entry is marked with the
  // fwmark routing tag of an upstream network interface, the connection will be
  // pinned to that network interface if conntrack fwmark restore is set for the
  // source.
  virtual void StartConnectionPinning(const std::string& ext_ifname);
  virtual void StopConnectionPinning(const std::string& ext_ifname);
  // Starts or stops VPN routing for:
  //  - Local traffic from sockets of binaries running under uids eligible to be
  //  routed
  //    through VPN connections. These uids are defined by |kLocalSourceTypes|
  //    in routing_service.h
  //  - Forwarded traffic from downstream network interfaces tracking the
  //  default network.
  virtual void StartVpnRouting(const std::string& vpn_ifname);
  virtual void StopVpnRouting(const std::string& vpn_ifname);

  // Starts and stops VPN lockdown mode. When patchpanel VPN lockdown is enabled
  // and no VPN connection exists, any non-ARC traffic that would be routed to a
  // VPN connection is instead rejected in iptables. ARC traffic is ignored
  // because Android already implements VPN lockdown.
  virtual void SetVpnLockdown(bool enable_vpn_lockdown);

  // Methods supporting IPv6 configuration for ARC.
  virtual bool MaskInterfaceFlags(const std::string& ifname,
                                  uint16_t on,
                                  uint16_t off = 0);

  virtual bool AddIPv6HostRoute(const std::string& ifname,
                                const std::string& ipv6_addr,
                                int ipv6_prefix_len);
  virtual void RemoveIPv6HostRoute(const std::string& ifname,
                                   const std::string& ipv6_addr,
                                   int ipv6_prefix_len);

  virtual bool AddIPv6Address(const std::string& ifname,
                              const std::string& ipv6_addr);
  virtual void RemoveIPv6Address(const std::string& ifname,
                                 const std::string& ipv6_addr);

  // Adds (or deletes) a route to direct to |gateway_addr| the traffic destined
  // to the subnet defined by |addr| and |netmask|.
  virtual bool AddIPv4Route(uint32_t gateway_addr,
                            uint32_t addr,
                            uint32_t netmask);
  virtual bool DeleteIPv4Route(uint32_t gateway_addr,
                               uint32_t addr,
                               uint32_t netmask);
  // Adds (or deletes) a route to direct to |ifname| the traffic destined to the
  // subnet defined by |addr| and |netmask|.
  virtual bool AddIPv4Route(const std::string& ifname,
                            uint32_t addr,
                            uint32_t netmask);
  virtual bool DeleteIPv4Route(const std::string& ifname,
                               uint32_t addr,
                               uint32_t netmask);

  // Adds (or deletes) an iptables rule for ADB port forwarding.
  virtual bool AddAdbPortForwardRule(const std::string& ifname);
  virtual void DeleteAdbPortForwardRule(const std::string& ifname);

  // Adds (or deletes) an iptables rule for ADB port access.
  virtual bool AddAdbPortAccessRule(const std::string& ifname);
  virtual void DeleteAdbPortAccessRule(const std::string& ifname);

  // Enables or disables netfilter conntrack helpers.
  virtual bool SetConntrackHelpers(bool enable_helpers);
  // Allows (or stops allowing) loopback IPv4 addresses as valid sources or
  // destinations during IPv4 routing for |ifname|. This lets connections
  // originated from guests like ARC or Crostini be accepted on the host and
  // should be used carefully in conjunction with firewall port access rules to
  // only allow very specific connection patterns.
  virtual bool SetRouteLocalnet(const std::string& ifname, bool enable);
  // Adds all |modules| into the kernel using modprobe.
  virtual bool ModprobeAll(const std::vector<std::string>& modules);

  // Create (or delete) DNAT rules for sending unsollicited traffic inbound on
  // interface |ifname| to |ipv4_addr|. This is used for implementing
  // transparent ARC inbound connections to Android Apps listening on the
  // network.
  virtual void AddInboundIPv4DNAT(const std::string& ifname,
                                  const std::string& ipv4_addr);
  virtual void RemoveInboundIPv4DNAT(const std::string& ifname,
                                     const std::string& ipv4_addr);

  // Create (or delete) DNAT rules for redirecting DNS queries from system
  // services to the nameservers of a particular physical networks. These
  // DNAT rules are only applied if a VPN is connected and allows system
  // services to resolve hostnames even if a VPN application configures DNS
  // addresses only routable through the VPN (b/178331695).
  // TODO(b/171157837) Replaces these rules with the system DNS proxy.
  bool AddRedirectDnsRule(const std::string& ifname,
                          const std::string dns_ipv4_addr);
  bool RemoveRedirectDnsRule(const std::string& ifname);

  // Add, remove, or flush chain |chain| in table |table|.
  bool AddChain(IpFamily family,
                const std::string& table,
                const std::string& name);
  bool RemoveChain(IpFamily family,
                   const std::string& table,
                   const std::string& name);
  bool FlushChain(IpFamily family,
                  const std::string& table,
                  const std::string& name);
  // Manipulates a chain |chain| in table |table|.
  virtual bool ModifyChain(IpFamily family,
                           const std::string& table,
                           const std::string& op,
                           const std::string& chain,
                           bool log_failures = true);
  // Sends an iptables command for table |table|.
  virtual bool ModifyIptables(IpFamily family,
                              const std::string& table,
                              const std::vector<std::string>& argv,
                              bool log_failures = true);
  // Dumps the iptables chains rules for the table |table|. |family| must be
  // either IPv4 or IPv6.
  virtual std::string DumpIptables(IpFamily family, const std::string& table);

  // Changes firewall rules based on |request|, allowing ingress traffic to a
  // port, forwarding ingress traffic to a port into ARC or Crostini, or
  // restricting localhost ports for listen(). This function corresponds to
  // the ModifyPortRule method of patchpanel DBus API.
  virtual bool ModifyPortRule(const patchpanel::ModifyPortRuleRequest& request);

 private:
  // Attempts to flush all built-in iptables chains used by patchpanel, and to
  // delete all additionals chains created by patchpanel for routing. Traffic
  // accounting chains are not deleted.
  void ResetIptables();
  // Creates a virtual interface pair.
  bool AddVirtualInterfacePair(const std::string& netns_name,
                               const std::string& veth_ifname,
                               const std::string& peer_ifname);
  // Sets the configuration of an interface.
  bool ConfigureInterface(const std::string& ifname,
                          const MacAddress& mac_addr,
                          uint32_t ipv4_addr,
                          uint32_t ipv4_prefix_len,
                          bool up,
                          bool enable_multicast);
  // Sets the link status.
  bool ToggleInterface(const std::string& ifname, bool up);
  bool ModifyChromeDnsRedirect(IpFamily family,
                               const DnsRedirectionRule& rule,
                               const std::string& op);
  bool ModifyRedirectDnsDNATRule(const std::string& op,
                                 const std::string& protocol,
                                 const std::string& ifname,
                                 const std::string& dns_ipv4_addr);
  bool ModifyDnsProxyMasquerade(IpFamily family,
                                const std::string& op,
                                const std::string& chain);
  bool ModifyRedirectDnsJumpRule(IpFamily family,
                                 const std::string& op,
                                 const std::string& chain,
                                 const std::string& ifname,
                                 const std::string& target_chain,
                                 Fwmark mark = {},
                                 Fwmark mask = {},
                                 bool redirect_on_mark = false);
  bool ModifyDnsRedirectionSkipVpnRule(IpFamily family, const std::string& op);

  // Create (or delete) DNAT rules for redirecting DNS queries to a DNS proxy.
  bool ModifyDnsProxyDNAT(IpFamily family,
                          const DnsRedirectionRule& rule,
                          const std::string& op,
                          const std::string& ifname,
                          const std::string& chain);

  bool ModifyConnmarkSet(IpFamily family,
                         const std::string& chain,
                         const std::string& op,
                         Fwmark mark,
                         Fwmark mask);
  bool ModifyConnmarkRestore(IpFamily family,
                             const std::string& chain,
                             const std::string& op,
                             const std::string& iif,
                             Fwmark mask);
  bool ModifyConnmarkSave(IpFamily family,
                          const std::string& chain,
                          const std::string& op,
                          Fwmark mask);
  bool ModifyFwmarkRoutingTag(const std::string& chain,
                              const std::string& op,
                              Fwmark routing_mark);
  bool ModifyFwmarkSourceTag(const std::string& chain,
                             const std::string& op,
                             TrafficSource source);
  bool ModifyFwmarkDefaultLocalSourceTag(const std::string& op,
                                         TrafficSource source);
  bool ModifyFwmarkLocalSourceTag(const std::string& op,
                                  const LocalSourceSpecs& source);
  bool ModifyFwmark(IpFamily family,
                    const std::string& chain,
                    const std::string& op,
                    const std::string& iif,
                    const std::string& uid_name,
                    uint32_t classid,
                    Fwmark mark,
                    Fwmark mask,
                    bool log_failures = true);
  bool ModifyJumpRule(IpFamily family,
                      const std::string& table,
                      const std::string& op,
                      const std::string& chain,
                      const std::string& target,
                      const std::string& iif,
                      const std::string& oif,
                      bool log_failures = true);
  bool ModifyFwmarkVpnJumpRule(const std::string& chain,
                               const std::string& op,
                               Fwmark mark,
                               Fwmark mask);
  bool ModifyFwmarkSkipVpnJumpRule(const std::string& chain,
                                   const std::string& op,
                                   const std::string& uid,
                                   bool log_failures = true);
  bool ModifyRtentry(ioctl_req_t op, struct rtentry* route);

  std::unique_ptr<MinijailedProcessRunner> process_runner_;
  std::unique_ptr<Firewall> firewall_;
  // Owned by Manager
  System* system_;

  FRIEND_TEST(DatapathTest, AddInboundIPv4DNAT);
  FRIEND_TEST(DatapathTest, AddVirtualInterfacePair);
  FRIEND_TEST(DatapathTest, ConfigureInterface);
  FRIEND_TEST(DatapathTest, RemoveInboundIPv4DNAT);
  FRIEND_TEST(DatapathTest, RemoveOutboundIPv4SNATMark);
  FRIEND_TEST(DatapathTest, ToggleInterface);

  // A map used for remembering the interface index of an interface. This
  // information is necessary when cleaning up iptables fwmark rules that
  // directly references the interface index. When removing these rules on
  // an RTM_DELLINK event, the interface index cannot be retrieved anymore.
  // A new entry is only added when a new upstream network interface appears,
  // and entries are not removed.
  // TODO(b/161507671) Rely on RoutingService to obtain this information once
  // shill/routing_table.cc has been migrated to patchpanel.
  std::map<std::string, int> if_nametoindex_;

  // A map used for tracking the primary IPv4 dns address associated to a given
  // Shill Device known by its interface name. This is used for redirecting
  // DNS queries of system services when a VPN is connected.
  std::map<std::string, std::string> physical_dns_addresses_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_DATAPATH_H_
