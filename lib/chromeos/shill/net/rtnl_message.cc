// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/rtnl_message.h"

#include <net/if.h>  // NB: order matters; this conflicts with <linux/if.h>
#include <arpa/inet.h>
#include <linux/fib_rules.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include <map>
#include <memory>
#include <optional>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "shill/net/ndisc.h"

namespace shill {

namespace {

using flags_info_t = std::vector<std::pair<uint32_t, std::string>>;

// Helper for pretty printing flags
std::string PrintFlags(uint32_t flags,
                       const flags_info_t& flags_info,
                       const std::string& separator = " | ") {
  std::string str;
  if (flags == 0)
    return str;
  std::string sep = "";
  for (const auto& flag_descr : flags_info) {
    if ((flags & flag_descr.first) == 0)
      continue;
    str += sep;
    str += flag_descr.second;
    sep = separator;
  }
  return str;
}

const flags_info_t kIfaFlags = {
    {IFA_F_TEMPORARY, "TEMPORARY"},
    {IFA_F_NODAD, "NODAD"},
    {IFA_F_OPTIMISTIC, "OPTIMISTIC"},
    {IFA_F_DADFAILED, "DADFAILED"},
    {IFA_F_HOMEADDRESS, "HOMEADDRESS"},
    {IFA_F_DEPRECATED, "DEPRECATED"},
    {IFA_F_TENTATIVE, "TENTATIVE"},
    {IFA_F_PERMANENT, "PERMANENT"},
    {IFA_F_MANAGETEMPADDR, "MANAGETEMPADDR"},
    {IFA_F_NOPREFIXROUTE, "NOPREFIXROUTE"},
    {IFA_F_MCAUTOJOIN, "MCAUTOJOIN"},
    {IFA_F_STABLE_PRIVACY, "STABLE_PRIVACY"},
};

// Flag names for Link events. Defined in uapi/linux/if.h
const flags_info_t kNetDeviceFlags = {
    {IFF_ALLMULTI, "ALLMULTI"},
    {IFF_AUTOMEDIA, "AUTOMEDIA"},
    {IFF_BROADCAST, "BROADCAST"},
    {IFF_DEBUG, "DEBUG"},
    {IFF_DORMANT, "DORMANT"},
    {IFF_DYNAMIC, "DYNAMIC"},
    {IFF_ECHO, "ECHO"},
    {IFF_LOOPBACK, "LOOPBACK"},
    {IFF_LOWER_UP, "LOWER_UP"},
    {IFF_MASTER, "MASTER"},
    {IFF_MULTICAST, "MULTICAST"},
    {IFF_NOARP, "NOARP"},
    {IFF_NOTRAILERS, "NOTRAILERS"},
    {IFF_POINTOPOINT, "POINTOPOINT"},
    {IFF_PORTSEL, "PORTSEL"},
    {IFF_PROMISC, "PROMISC"},
    {IFF_RUNNING, "RUNNING"},
    {IFF_SLAVE, "SLAVE"},
    {IFF_UP, "UP"},
};

// Fine grained link types. Defined in uapi/linux/if_arp.h
std::map<uint16_t, std::string> kNetDeviceTypes = {
    {ARPHRD_NETROM, "NETROM"},
    {ARPHRD_ETHER, "ETHER"},
    {ARPHRD_EETHER, "EETHER"},
    {ARPHRD_AX25, "AX25"},
    {ARPHRD_PRONET, "PRONET"},
    {ARPHRD_CHAOS, "CHAOS"},
    {ARPHRD_IEEE802, "IEEE802"},
    {ARPHRD_ARCNET, "ARCNET"},
    {ARPHRD_APPLETLK, "APPLETLK"},
    {ARPHRD_DLCI, "DLCI"},
    {ARPHRD_ATM, "ATM"},
    {ARPHRD_METRICOM, "METRICOM"},
    {ARPHRD_IEEE1394, "IEEE1394"},
    {ARPHRD_EUI64, "EUI64"},
    {ARPHRD_INFINIBAND, "INFINIBAND"},
    {ARPHRD_SLIP, "SLIP"},
    {ARPHRD_CSLIP, "CSLIP"},
    {ARPHRD_SLIP6, "SLIP6"},
    {ARPHRD_CSLIP6, "CSLIP6"},
    {ARPHRD_RSRVD, "RSRVD"},
    {ARPHRD_ADAPT, "ADAPT"},
    {ARPHRD_ROSE, "ROSE"},
    {ARPHRD_X25, "X25"},
    {ARPHRD_HWX25, "HWX25"},
    {ARPHRD_CAN, "CAN"},
    {ARPHRD_PPP, "PPP"},
    {ARPHRD_CISCO, "CISCO"},
    {ARPHRD_HDLC, "HDLC"},
    {ARPHRD_LAPB, "LAPB"},
    {ARPHRD_DDCMP, "DDCMP"},
    {ARPHRD_RAWHDLC, "RAWHDLC"},
    {ARPHRD_RAWIP, "RAWIP"},
    {ARPHRD_TUNNEL, "TUNNEL"},
    {ARPHRD_TUNNEL6, "TUNNEL6"},
    {ARPHRD_FRAD, "FRAD"},
    {ARPHRD_SKIP, "SKIP"},
    {ARPHRD_LOOPBACK, "LOOPBACK"},
    {ARPHRD_LOCALTLK, "LOCALTLK"},
    {ARPHRD_FDDI, "FDDI"},
    {ARPHRD_BIF, "BIF"},
    {ARPHRD_SIT, "SIT"},
    {ARPHRD_IPDDP, "IPDDP"},
    {ARPHRD_IPGRE, "IPGRE"},
    {ARPHRD_PIMREG, "PIMREG"},
    {ARPHRD_HIPPI, "HIPPI"},
    {ARPHRD_ASH, "ASH"},
    {ARPHRD_ECONET, "ECONET"},
    {ARPHRD_IRDA, "IRDA"},
    {ARPHRD_FCPP, "FCPP"},
    {ARPHRD_FCAL, "FCAL"},
    {ARPHRD_FCPL, "FCPL"},
    {ARPHRD_FCFABRIC, "FCFABRIC"},
    {ARPHRD_IEEE802_TR, "IEEE802_TR"},
    {ARPHRD_IEEE80211, "IEEE80211"},
    {ARPHRD_IEEE80211_PRISM, "IEEE80211_PRISM"},
    {ARPHRD_IEEE80211_RADIOTAP, "IEEE80211_RADIOTAP"},
    {ARPHRD_IEEE802154, "IEEE802154  "},
    {ARPHRD_IEEE802154_MONITOR, "IEEE802154_MONITOR"},
    {ARPHRD_PHONET, "PHONET"},
    {ARPHRD_PHONET_PIPE, "PHONET_PIPE"},
    {ARPHRD_CAIF, "CAIF"},
    {ARPHRD_IP6GRE, "IP6GRE"},
    {ARPHRD_NETLINK, "NETLINK"},
    {ARPHRD_6LOWPAN, "6LOWPAN"},
    {ARPHRD_VSOCKMON, "VSOCKMON"},
    {ARPHRD_VOID, "VOID"},
    {ARPHRD_NONE, "NONE"},
};

// Route types. Defined in uapi/linux/rtnetlink.h
std::map<uint8_t, std::string> kRouteTypes = {
    {RTN_UNSPEC, "UNSPEC"},
    {RTN_UNICAST, "UNICAST"},
    {RTN_LOCAL, "LOCAL"},
    {RTN_BROADCAST, "BROADCAST"},
    {RTN_ANYCAST, "ANYCAST"},
    {RTN_MULTICAST, "MULTICAST"},
    {RTN_BLACKHOLE, "BLACKHOLE"},
    {RTN_UNREACHABLE, "UNREACHABLE"},
    {RTN_PROHIBIT, "PROHIBIT"},
    {RTN_THROW, "THROW"},
    {RTN_NAT, "NAT"},
    {RTN_XRESOLVE, "XRESOLVE"},
};

// Route protocols. Defined in uapi/linux/rtnetlink.h
std::map<uint8_t, std::string> kRouteProtocols = {
    {RTPROT_UNSPEC, "UNSPEC"},
    {RTPROT_REDIRECT, "REDIRECT"},
    {RTPROT_KERNEL, "KERNEL"},
    {RTPROT_BOOT, "BOOT"},
    {RTPROT_STATIC, "STATIC"},
    {RTPROT_GATED, "GATED"},
    {RTPROT_RA, "RA"},
    {RTPROT_MRT, "MRT"},
    {RTPROT_ZEBRA, "ZEBRA"},
    {RTPROT_BIRD, "BIRD"},
    {RTPROT_DNROUTED, "DNROUTED"},
    {RTPROT_XORP, "XORP"},
    {RTPROT_NTK, "NTK"},
    {RTPROT_DHCP, "DHCP"},
    {RTPROT_MROUTED, "MROUTED"},
    {RTPROT_BABEL, "BABEL"},
    // The following protocols are not defined on Linux 4.14
    {186 /* RTPROT_BGP */, "BGP"},
    {187 /* RTPROT_ISIS */, "ISIS"},
    {188 /* RTPROT_OSPF */, "OSPF"},
    {189 /* RTPROT_RIP */, "RIP"},
    {192 /* RTPROT_EIGRP */, "EIGRP"},
};

// Rule actions. Defined in struct fib_rule_hdr in uapi/linux/fib_rules.h such
// that it aligns with the |rtm_type| field of struct rtmsg defined in
// uapi/linux/rtnetlink.h. Possible values are defined in
// uapi/linux/fib_rules.h.
std::map<uint8_t, std::string> kRuleActions = {
    {FR_ACT_UNSPEC, "UNSPEC"},       {FR_ACT_TO_TBL, "TO_TBL"},
    {FR_ACT_GOTO, "GOTO"},           {FR_ACT_NOP, "NOP"},
    {FR_ACT_RES3, "RES3"},           {FR_ACT_RES4, "RES4"},
    {FR_ACT_BLACKHOLE, "BLACKHOLE"}, {FR_ACT_UNREACHABLE, "UNREACHABLE"},
    {FR_ACT_PROHIBIT, "PROHIBIT"},
};

// Helper function to return route protocol names defined by the kernel.
// User reserved protocol values are returned as decimal numbers.
std::string GetRouteProtocol(uint8_t protocol) {
  const auto it = kRouteProtocols.find(protocol);
  if (it == kRouteProtocols.end())
    return std::to_string(protocol);
  return it->second;
}

std::unique_ptr<RTNLAttrMap> ParseAttrs(struct rtattr* data, int len) {
  RTNLAttrMap attrs;
  ByteString attr_bytes(reinterpret_cast<const char*>(data), len);

  while (data && RTA_OK(data, len)) {
    attrs[data->rta_type] = ByteString(
        reinterpret_cast<unsigned char*>(RTA_DATA(data)), RTA_PAYLOAD(data));
    // Note: RTA_NEXT() performs subtraction on 'len'. It's important that
    // 'len' is a signed integer, so underflow works properly.
    data = RTA_NEXT(data, len);
  }

  if (len) {
    LOG(ERROR) << "Error parsing RTNL attributes <" << attr_bytes.HexEncode()
               << ">, trailing length: " << len;
    return nullptr;
  }

  return std::make_unique<RTNLAttrMap>(attrs);
}

// Returns the interface name for the device with interface index |ifindex|, or
// returns an empty string if it fails to find the interface.
std::string IndexToName(int ifindex) {
  char buf[IFNAMSIZ] = {};
  if_indextoname(ifindex, buf);
  return std::string(buf);
}

}  // namespace

struct RTNLHeader {
  RTNLHeader() { memset(this, 0, sizeof(*this)); }
  struct nlmsghdr hdr;
  union {
    struct ifinfomsg ifi;
    struct ifaddrmsg ifa;
    struct rtmsg rtm;
    struct nduseroptmsg nd_user_opt;
    struct ndmsg ndm;
  };
};

std::string RTNLMessage::NeighborStatus::ToString() const {
  return base::StringPrintf("NeighborStatus state %d flags %X type %d", state,
                            flags, type);
}

std::string RTNLMessage::RdnssOption::ToString() const {
  return base::StringPrintf("RdnssOption lifetime %d", lifetime);
}

ByteString RTNLMessage::PackAttrs(const RTNLAttrMap& attrs) {
  ByteString attributes;

  for (const auto& pair : attrs) {
    size_t len = RTA_LENGTH(pair.second.GetLength());
    struct rtattr rt_attr = {
        // Linter discourages 'unsigned short', but 'unsigned short' is used in
        // the UAPI.
        static_cast<unsigned short>(len),  // NOLINT(runtime/int)
        pair.first,
    };
    ByteString header(reinterpret_cast<unsigned char*>(&rt_attr),
                      sizeof(rt_attr));
    header.Resize(RTA_ALIGN(header.GetLength()));
    attributes.Append(header);

    ByteString data(pair.second);
    data.Resize(RTA_ALIGN(data.GetLength()));
    attributes.Append(data);
  }

  return attributes;
}

RTNLMessage::RTNLMessage()
    : type_(kTypeUnknown),
      mode_(kModeUnknown),
      flags_(0),
      seq_(0),
      pid_(0),
      interface_index_(0),
      family_(IPAddress::kFamilyUnknown) {}

RTNLMessage::RTNLMessage(Type type,
                         Mode mode,
                         uint16_t flags,
                         uint32_t seq,
                         uint32_t pid,
                         int32_t interface_index,
                         IPAddress::Family family)
    : type_(type),
      mode_(mode),
      flags_(flags),
      seq_(seq),
      pid_(pid),
      interface_index_(interface_index),
      family_(family) {}

bool RTNLMessage::Decode(const ByteString& msg) {
  bool ret = DecodeInternal(msg);
  if (!ret) {
    Reset();
  }
  return ret;
}

bool RTNLMessage::DecodeInternal(const ByteString& msg) {
  const RTNLHeader* hdr =
      reinterpret_cast<const RTNLHeader*>(msg.GetConstData());

  if (msg.GetLength() < sizeof(hdr->hdr) ||
      msg.GetLength() < hdr->hdr.nlmsg_len)
    return false;

  mode_ = kModeUnknown;
  switch (hdr->hdr.nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_NEWADDR:
    case RTM_NEWROUTE:
    case RTM_NEWRULE:
    case RTM_NEWNDUSEROPT:
    case RTM_NEWNEIGH:
      mode_ = kModeAdd;
      break;

    case RTM_DELLINK:
    case RTM_DELADDR:
    case RTM_DELROUTE:
    case RTM_DELRULE:
    case RTM_DELNEIGH:
      mode_ = kModeDelete;
      break;

    default:
      return false;
  }

  rtattr* attr_data = nullptr;
  int attr_length = 0;

  switch (hdr->hdr.nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
      if (!DecodeLink(hdr, &attr_data, &attr_length))
        return false;
      break;

    case RTM_NEWADDR:
    case RTM_DELADDR:
      if (!DecodeAddress(hdr, &attr_data, &attr_length))
        return false;
      break;

    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      if (!DecodeRoute(hdr, &attr_data, &attr_length))
        return false;
      break;

    case RTM_NEWRULE:
    case RTM_DELRULE:
      if (!DecodeRule(hdr, &attr_data, &attr_length))
        return false;
      break;

    case RTM_NEWNDUSEROPT:
      if (!DecodeNdUserOption(hdr, &attr_data, &attr_length))
        return false;
      break;

    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
      if (!DecodeNeighbor(hdr, &attr_data, &attr_length))
        return false;
      break;

    default:
      NOTREACHED();
  }

  flags_ = hdr->hdr.nlmsg_flags;
  seq_ = hdr->hdr.nlmsg_seq;
  pid_ = hdr->hdr.nlmsg_pid;

  std::unique_ptr<RTNLAttrMap> attrs = ParseAttrs(attr_data, attr_length);
  if (!attrs) {
    attributes_.clear();
    return false;
  }

  for (const auto& pair : *attrs) {
    SetAttribute(pair.first, pair.second);
  }
  return true;
}

bool RTNLMessage::DecodeLink(const RTNLHeader* hdr,
                             rtattr** attr_data,
                             int* attr_length) {
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(hdr->ifi))) {
    return false;
  }

  *attr_data = IFLA_RTA(NLMSG_DATA(&hdr->hdr));
  *attr_length = IFLA_PAYLOAD(&hdr->hdr);

  type_ = kTypeLink;
  family_ = hdr->ifi.ifi_family;
  interface_index_ = hdr->ifi.ifi_index;

  std::unique_ptr<RTNLAttrMap> attrs = ParseAttrs(*attr_data, *attr_length);
  if (!attrs)
    return false;

  std::optional<std::string> kind_option;

  if (base::Contains(*attrs, IFLA_LINKINFO)) {
    ByteString& bytes = attrs->find(IFLA_LINKINFO)->second;
    struct rtattr* link_data =
        reinterpret_cast<struct rtattr*>(bytes.GetData());
    size_t link_len = bytes.GetLength();
    std::unique_ptr<RTNLAttrMap> linkinfo = ParseAttrs(link_data, link_len);

    if (linkinfo && base::Contains(*linkinfo, IFLA_INFO_KIND)) {
      ByteString& kindBytes = linkinfo->find(IFLA_INFO_KIND)->second;
      const char* kind = reinterpret_cast<const char*>(kindBytes.GetData());
      std::string kind_string(kind, strnlen(kind, kindBytes.GetLength()));
      if (base::IsStringASCII(kind_string))
        kind_option = kind_string;
      else
        LOG(ERROR) << base::StringPrintf(
            "Invalid kind <%s>, interface index %d",
            kindBytes.HexEncode().c_str(), interface_index_);
    }
  }

  set_link_status(LinkStatus(hdr->ifi.ifi_type, hdr->ifi.ifi_flags,
                             hdr->ifi.ifi_change, kind_option));

  return true;
}

bool RTNLMessage::DecodeAddress(const RTNLHeader* hdr,
                                rtattr** attr_data,
                                int* attr_length) {
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(hdr->ifa))) {
    return false;
  }
  *attr_data = IFA_RTA(NLMSG_DATA(&hdr->hdr));
  *attr_length = IFA_PAYLOAD(&hdr->hdr);

  type_ = kTypeAddress;
  family_ = hdr->ifa.ifa_family;
  interface_index_ = hdr->ifa.ifa_index;
  set_address_status(AddressStatus(hdr->ifa.ifa_prefixlen, hdr->ifa.ifa_flags,
                                   hdr->ifa.ifa_scope));
  return true;
}

bool RTNLMessage::DecodeRoute(const RTNLHeader* hdr,
                              rtattr** attr_data,
                              int* attr_length) {
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(hdr->rtm))) {
    return false;
  }
  *attr_data = RTM_RTA(NLMSG_DATA(&hdr->hdr));
  *attr_length = RTM_PAYLOAD(&hdr->hdr);

  type_ = kTypeRoute;
  family_ = hdr->rtm.rtm_family;
  set_route_status(RouteStatus(hdr->rtm.rtm_dst_len, hdr->rtm.rtm_src_len,
                               hdr->rtm.rtm_table, hdr->rtm.rtm_protocol,
                               hdr->rtm.rtm_scope, hdr->rtm.rtm_type,
                               hdr->rtm.rtm_flags));
  return true;
}

bool RTNLMessage::DecodeRule(const RTNLHeader* hdr,
                             rtattr** attr_data,
                             int* attr_length) {
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(hdr->rtm))) {
    return false;
  }
  *attr_data = RTM_RTA(NLMSG_DATA(&hdr->hdr));
  *attr_length = RTM_PAYLOAD(&hdr->hdr);

  type_ = kTypeRule;
  family_ = hdr->rtm.rtm_family;
  set_route_status(RouteStatus(hdr->rtm.rtm_dst_len, hdr->rtm.rtm_src_len,
                               hdr->rtm.rtm_table, hdr->rtm.rtm_protocol,
                               hdr->rtm.rtm_scope, hdr->rtm.rtm_type,
                               hdr->rtm.rtm_flags));
  return true;
}

bool RTNLMessage::DecodeNdUserOption(const RTNLHeader* hdr,
                                     rtattr** attr_data,
                                     int* attr_length) {
  size_t min_payload_len = sizeof(hdr->nd_user_opt) +
                           sizeof(struct nduseroptmsg) +
                           sizeof(NDUserOptionHeader);
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(min_payload_len)) {
    return false;
  }

  interface_index_ = hdr->nd_user_opt.nduseropt_ifindex;
  family_ = hdr->nd_user_opt.nduseropt_family;

  // Verify IP family.
  if (family_ != IPAddress::kFamilyIPv6) {
    return false;
  }
  // Verify message must at-least contain the option header.
  if (hdr->nd_user_opt.nduseropt_opts_len < sizeof(NDUserOptionHeader)) {
    return false;
  }

  // Parse the option header.
  const NDUserOptionHeader* nd_user_option_header =
      reinterpret_cast<const NDUserOptionHeader*>(
          reinterpret_cast<const uint8_t*>(&hdr->nd_user_opt) +
          sizeof(struct nduseroptmsg));
  uint32_t lifetime = ntohl(nd_user_option_header->lifetime);

  // Verify option length.
  // The length field in the header is in units of 8 octets.
  int opt_len = static_cast<int>(nd_user_option_header->length) * 8;
  if (opt_len != hdr->nd_user_opt.nduseropt_opts_len) {
    return false;
  }

  // Determine option data pointer and data length.
  const uint8_t* option_data =
      reinterpret_cast<const uint8_t*>(nd_user_option_header + 1);
  int data_len = opt_len - sizeof(NDUserOptionHeader);
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(min_payload_len + data_len)) {
    return false;
  }

  if (nd_user_option_header->type == ND_OPT_DNSSL) {
    // TODO(zqiu): Parse DNSSL (DNS Search List) option.
    type_ = kTypeDnssl;
    return true;
  } else if (nd_user_option_header->type == ND_OPT_RDNSS) {
    // Parse RNDSS (Recursive DNS Server) option.
    type_ = kTypeRdnss;
    return ParseRdnssOption(option_data, data_len, lifetime);
  }

  return false;
}

bool RTNLMessage::ParseRdnssOption(const uint8_t* data,
                                   int length,
                                   uint32_t lifetime) {
  const int addr_length = IPAddress::GetAddressLength(IPAddress::kFamilyIPv6);

  // Verify data size are multiple of individual address size.
  if (length % addr_length != 0) {
    return false;
  }

  // Parse the DNS server addresses.
  std::vector<IPAddress> dns_server_addresses;
  while (length > 0) {
    dns_server_addresses.push_back(
        IPAddress(IPAddress::kFamilyIPv6, ByteString(data, addr_length)));
    length -= addr_length;
    data += addr_length;
  }
  set_rdnss_option(RdnssOption(lifetime, dns_server_addresses));
  return true;
}

bool RTNLMessage::DecodeNeighbor(const RTNLHeader* hdr,
                                 rtattr** attr_data,
                                 int* attr_length) {
  if (hdr->hdr.nlmsg_len < NLMSG_LENGTH(sizeof(hdr->ndm))) {
    return false;
  }

  interface_index_ = hdr->ndm.ndm_ifindex;
  family_ = hdr->ndm.ndm_family;
  type_ = kTypeNeighbor;

  *attr_data = RTM_RTA(NLMSG_DATA(&hdr->hdr));
  *attr_length = RTM_PAYLOAD(&hdr->hdr);

  set_neighbor_status(NeighborStatus(hdr->ndm.ndm_state, hdr->ndm.ndm_flags,
                                     hdr->ndm.ndm_type));
  return true;
}

ByteString RTNLMessage::Encode() const {
  if (type_ != kTypeLink && type_ != kTypeAddress && type_ != kTypeRoute &&
      type_ != kTypeRule && type_ != kTypeNeighbor) {
    return ByteString();
  }

  RTNLHeader hdr;
  hdr.hdr.nlmsg_flags = flags_;
  hdr.hdr.nlmsg_seq = seq_;
  hdr.hdr.nlmsg_pid = pid_;

  switch (type_) {
    case kTypeLink:
      if (!EncodeLink(&hdr)) {
        return ByteString();
      }
      break;

    case kTypeAddress:
      if (!EncodeAddress(&hdr)) {
        return ByteString();
      }
      break;

    case kTypeRoute:
    case kTypeRule:
      if (!EncodeRoute(&hdr)) {
        return ByteString();
      }
      break;

    case kTypeNeighbor:
      if (!EncodeNeighbor(&hdr)) {
        return ByteString();
      }
      break;

    default:
      NOTREACHED();
  }

  if (mode_ == kModeGet) {
    hdr.hdr.nlmsg_flags |= NLM_F_REQUEST | NLM_F_DUMP;
  }

  size_t header_length = hdr.hdr.nlmsg_len;
  ByteString attributes = PackAttrs(attributes_);
  hdr.hdr.nlmsg_len = NLMSG_ALIGN(hdr.hdr.nlmsg_len) + attributes.GetLength();
  ByteString packet(reinterpret_cast<unsigned char*>(&hdr), header_length);
  packet.Append(attributes);

  return packet;
}

bool RTNLMessage::EncodeLink(RTNLHeader* hdr) const {
  switch (mode_) {
    case kModeAdd:
      hdr->hdr.nlmsg_type = RTM_NEWLINK;
      break;
    case kModeDelete:
      hdr->hdr.nlmsg_type = RTM_DELLINK;
      break;
    case kModeGet:
    case kModeQuery:
      hdr->hdr.nlmsg_type = RTM_GETLINK;
      break;
    default:
      NOTIMPLEMENTED();
      return false;
  }
  hdr->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(hdr->ifi));
  hdr->ifi.ifi_family = family_;
  hdr->ifi.ifi_index = interface_index_;
  hdr->ifi.ifi_type = link_status_.type;
  hdr->ifi.ifi_flags = link_status_.flags;
  hdr->ifi.ifi_change = link_status_.change;
  return true;
}

bool RTNLMessage::EncodeAddress(RTNLHeader* hdr) const {
  switch (mode_) {
    case kModeAdd:
      hdr->hdr.nlmsg_type = RTM_NEWADDR;
      break;
    case kModeDelete:
      hdr->hdr.nlmsg_type = RTM_DELADDR;
      break;
    case kModeGet:
    case kModeQuery:
      hdr->hdr.nlmsg_type = RTM_GETADDR;
      break;
    default:
      NOTIMPLEMENTED();
      return false;
  }
  hdr->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(hdr->ifa));
  hdr->ifa.ifa_family = family_;
  hdr->ifa.ifa_prefixlen = address_status_.prefix_len;
  hdr->ifa.ifa_flags = address_status_.flags;
  hdr->ifa.ifa_scope = address_status_.scope;
  hdr->ifa.ifa_index = interface_index_;
  return true;
}

bool RTNLMessage::EncodeRoute(RTNLHeader* hdr) const {
  // Routes and routing rules are both based on struct rtm
  switch (mode_) {
    case kModeAdd:
      hdr->hdr.nlmsg_type = (type_ == kTypeRoute) ? RTM_NEWROUTE : RTM_NEWRULE;
      break;
    case kModeDelete:
      hdr->hdr.nlmsg_type = (type_ == kTypeRoute) ? RTM_DELROUTE : RTM_DELRULE;
      break;
    case kModeGet:
    case kModeQuery:
      hdr->hdr.nlmsg_type = (type_ == kTypeRoute) ? RTM_GETROUTE : RTM_GETRULE;
      break;
    default:
      NOTIMPLEMENTED();
      return false;
  }
  hdr->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(hdr->rtm));
  hdr->rtm.rtm_family = family_;
  hdr->rtm.rtm_dst_len = route_status_.dst_prefix;
  hdr->rtm.rtm_src_len = route_status_.src_prefix;
  hdr->rtm.rtm_table = route_status_.table;
  hdr->rtm.rtm_protocol = route_status_.protocol;
  hdr->rtm.rtm_scope = route_status_.scope;
  hdr->rtm.rtm_type = route_status_.type;
  hdr->rtm.rtm_flags = route_status_.flags;
  return true;
}

bool RTNLMessage::EncodeNeighbor(RTNLHeader* hdr) const {
  switch (mode_) {
    case kModeAdd:
      hdr->hdr.nlmsg_type = RTM_NEWNEIGH;
      break;
    case kModeDelete:
      hdr->hdr.nlmsg_type = RTM_DELNEIGH;
      break;
    case kModeGet:
    case kModeQuery:
      hdr->hdr.nlmsg_type = RTM_GETNEIGH;
      break;
    default:
      NOTIMPLEMENTED();
      return false;
  }
  hdr->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(hdr->ndm));
  hdr->ndm.ndm_family = family_;
  hdr->ndm.ndm_ifindex = interface_index_;
  hdr->ndm.ndm_state = neighbor_status_.state;
  hdr->ndm.ndm_flags = neighbor_status_.flags;
  hdr->ndm.ndm_type = neighbor_status_.type;
  return true;
}

void RTNLMessage::Reset() {
  type_ = kTypeUnknown;
  mode_ = kModeUnknown;
  flags_ = 0;
  seq_ = 0;
  pid_ = 0;
  interface_index_ = 0;
  family_ = IPAddress::kFamilyUnknown;
  link_status_ = LinkStatus();
  address_status_ = AddressStatus();
  route_status_ = RouteStatus();
  neighbor_status_ = NeighborStatus();
  rdnss_option_ = RdnssOption();
  attributes_.clear();
}

uint32_t RTNLMessage::GetUint32Attribute(uint16_t attr) const {
  uint32_t val = 0;
  GetAttribute(attr).ConvertToCPUUInt32(&val);
  return val;
}

std::string RTNLMessage::GetStringAttribute(uint16_t attr) const {
  if (!HasAttribute(attr))
    return "";
  ByteString bytes = GetAttribute(attr);
  size_t len = strnlen(bytes.GetConstCString(), bytes.GetLength());
  return std::string(bytes.GetConstCString(), len);
}

std::string RTNLMessage::GetIflaIfname() const {
  return GetStringAttribute(IFLA_IFNAME);
}

IPAddress RTNLMessage::GetIfaAddress() const {
  return IPAddress(family_, GetAttribute(IFA_ADDRESS),
                   address_status_.prefix_len);
}

uint32_t RTNLMessage::GetRtaTable() const {
  return GetUint32Attribute(RTA_TABLE);
}

IPAddress RTNLMessage::GetRtaDst() const {
  return IPAddress(family_, GetAttribute(RTA_DST), route_status_.dst_prefix);
}

IPAddress RTNLMessage::GetRtaSrc() const {
  return IPAddress(family_, GetAttribute(RTA_SRC), route_status_.src_prefix);
}

IPAddress RTNLMessage::GetRtaGateway() const {
  return IPAddress(family_, GetAttribute(RTA_GATEWAY));
}

uint32_t RTNLMessage::GetRtaOif() const {
  return GetUint32Attribute(RTA_OIF);
}

std::string RTNLMessage::GetRtaOifname() const {
  return IndexToName(GetRtaOif());
}

uint32_t RTNLMessage::GetRtaPriority() const {
  return GetUint32Attribute(RTA_PRIORITY);
}

uint32_t RTNLMessage::GetFraTable() const {
  return GetUint32Attribute(FRA_TABLE);
}

std::string RTNLMessage::GetFraOifname() const {
  return GetStringAttribute(FRA_OIFNAME);
}

std::string RTNLMessage::GetFraIifname() const {
  return GetStringAttribute(FRA_IIFNAME);
}

IPAddress RTNLMessage::GetFraSrc() const {
  return IPAddress(family_, GetAttribute(FRA_SRC), route_status_.src_prefix);
}

IPAddress RTNLMessage::GetFraDst() const {
  return IPAddress(family_, GetAttribute(FRA_DST), route_status_.dst_prefix);
}

uint32_t RTNLMessage::GetFraFwmark() const {
  return GetUint32Attribute(FRA_FWMARK);
}

uint32_t RTNLMessage::GetFraFwmask() const {
  return GetUint32Attribute(FRA_FWMASK);
}

uint32_t RTNLMessage::GetFraPriority() const {
  return GetUint32Attribute(FRA_PRIORITY);
}

void RTNLMessage::SetIflaInfoKind(const std::string& link_kind,
                                  const ByteString& info_data) {
  // The maximum length of IFLA_INFO_KIND attribute is MODULE_NAME_LEN, defined
  // in /include/linux/module.h, as (64 - sizeof(unsigned long)). Set it to a
  // fixed value here.
  constexpr uint32_t kMaxModuleNameLen = 56;
  if (link_kind.length() >= kMaxModuleNameLen) {
    LOG(DFATAL) << "link_kind is too long: " << link_kind;
  }
  link_status_.kind = link_kind;
  RTNLAttrMap link_info_map;
  link_info_map[IFLA_INFO_KIND] = ByteString{link_kind, true};
  if (!info_data.IsEmpty()) {
    link_info_map[IFLA_INFO_DATA] = info_data;
  }
  if (HasAttribute(IFLA_LINKINFO)) {
    LOG(DFATAL) << "IFLA_LINKINFO has already been set.";
  }
  SetAttribute(IFLA_LINKINFO, PackAttrs(link_info_map));
}

// static
std::string RTNLMessage::ModeToString(RTNLMessage::Mode mode) {
  switch (mode) {
    case RTNLMessage::kModeGet:
      return "Get";
    case RTNLMessage::kModeAdd:
      return "Add";
    case RTNLMessage::kModeDelete:
      return "Delete";
    case RTNLMessage::kModeQuery:
      return "Query";
    default:
      return "UnknownMode";
  }
}

// static
std::string RTNLMessage::TypeToString(RTNLMessage::Type type) {
  switch (type) {
    case RTNLMessage::kTypeLink:
      return "Link";
    case RTNLMessage::kTypeAddress:
      return "Address";
    case RTNLMessage::kTypeRoute:
      return "Route";
    case RTNLMessage::kTypeRule:
      return "Rule";
    case RTNLMessage::kTypeRdnss:
      return "Rdnss";
    case RTNLMessage::kTypeDnssl:
      return "Dnssl";
    case RTNLMessage::kTypeNeighbor:
      return "Neighbor";
    default:
      return "UnknownType";
  }
}

std::string RTNLMessage::ToString() const {
  // Include the space separator in |ip_family| to avoid double spaces for
  // messages with family AF_UNSPEC.
  std::string ip_family = " " + IPAddress::GetAddressFamilyName(family());
  std::string details;
  switch (type()) {
    case RTNLMessage::kTypeLink:
      ip_family = "";
      details = base::StringPrintf(
          "%s[%d] type %s flags <%s> change %X", GetIflaIfname().c_str(),
          interface_index_, kNetDeviceTypes[link_status_.type].c_str(),
          PrintFlags(link_status_.flags, kNetDeviceFlags, ",").c_str(),
          link_status_.change);
      if (link_status_.kind.has_value())
        details += " kind " + link_status_.kind.value();
      break;
    case RTNLMessage::kTypeAddress:
      details = base::StringPrintf(
          "%s/%d if %s[%d] flags %s scope %d",
          GetIfaAddress().ToString().c_str(), address_status_.prefix_len,
          IndexToName(interface_index_).c_str(), interface_index_,
          address_status_.flags
              ? PrintFlags(address_status_.flags, kIfaFlags).c_str()
              : "0",
          address_status_.scope);
      break;
    case RTNLMessage::kTypeRoute:
      if (HasAttribute(RTA_SRC))
        details +=
            base::StringPrintf("src %s/%d ", GetRtaSrc().ToString().c_str(),
                               route_status_.src_prefix);
      if (HasAttribute(RTA_DST))
        details +=
            base::StringPrintf("dst %s/%d ", GetRtaDst().ToString().c_str(),
                               route_status_.dst_prefix);
      if (HasAttribute(RTA_GATEWAY))
        details += "via " + GetRtaGateway().ToString() + " ";
      if (HasAttribute(RTA_OIF))
        details += base::StringPrintf("if %s[%d] ", GetRtaOifname().c_str(),
                                      GetRtaOif());
      details += base::StringPrintf(
          "table %d priority %d protocol %s type %s", GetRtaTable(),
          GetRtaPriority(), GetRouteProtocol(route_status_.protocol).c_str(),
          kRouteTypes[route_status_.type].c_str());
      break;
    case RTNLMessage::kTypeRule:
      // Rules are serialized via struct fib_rule_hdr which aligns with struct
      // rtmsg used for routes such that |type| corresponds to the rule action.
      // |protocol| and |scope| are currently unused as of Linux 5.6.
      if (HasAttribute(FRA_IIFNAME))
        details += "iif " + GetFraIifname() + " ";
      if (HasAttribute(FRA_OIFNAME))
        details += "oif " + GetFraOifname() = " ";
      if (HasAttribute(FRA_SRC))
        details +=
            base::StringPrintf("src %s/%d ", GetFraSrc().ToString().c_str(),
                               route_status_.src_prefix);
      if (HasAttribute(FRA_DST))
        details +=
            base::StringPrintf("dst %s/%d ", GetFraDst().ToString().c_str(),
                               route_status_.dst_prefix);
      if (HasAttribute(FRA_FWMARK))
        details += base::StringPrintf("fwmark 0x%X/0x%X ", GetFraFwmark(),
                                      GetFraFwmask());
      details += base::StringPrintf("table %d priority %d action %s flags %X",
                                    GetFraTable(), GetFraPriority(),
                                    kRuleActions[route_status_.type].c_str(),
                                    route_status_.flags);
      break;
    case RTNLMessage::kTypeRdnss:
    case RTNLMessage::kTypeDnssl:
      details = rdnss_option_.ToString();
      break;
    case RTNLMessage::kTypeNeighbor:
      details = neighbor_status_.ToString();
      break;
    default:
      break;
  }
  return base::StringPrintf("%s%s %s: %s", ModeToString(mode()).c_str(),
                            ip_family.c_str(), TypeToString(type()).c_str(),
                            details.c_str());
}

}  // namespace shill
