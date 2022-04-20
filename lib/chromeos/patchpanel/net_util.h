// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/in6.h>
#include <linux/vm_sockets.h>
#include <net/route.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <string>

#include <base/strings/stringprintf.h>
#include <brillo/brillo_export.h>

#include "patchpanel/mac_address_generator.h"

#ifndef PATCHPANEL_NET_UTIL_H_
#define PATCHPANEL_NET_UTIL_H_

namespace patchpanel {

// Reverses the byte order of the argument.
BRILLO_EXPORT constexpr uint32_t Byteswap32(uint32_t x) {
  return (x >> 24) | (x << 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000);
}

// Reverses the byte order of the argument.
BRILLO_EXPORT constexpr uint16_t Byteswap16(uint16_t x) {
  return (x >> 8) | (x << 8);
}

// Constexpr version of ntohl().
BRILLO_EXPORT constexpr uint32_t Ntohl(uint32_t x) {
  return Byteswap32(x);
}

// Constexpr version of htonl().
BRILLO_EXPORT constexpr uint32_t Htonl(uint32_t x) {
  return Byteswap32(x);
}

// Constexpr version of ntohs().
BRILLO_EXPORT constexpr uint16_t Ntohs(uint16_t x) {
  return Byteswap16(x);
}

// Constexpr version of htons().
BRILLO_EXPORT constexpr uint16_t Htons(uint16_t x) {
  return Byteswap16(x);
}

// Returns the network-byte order int32 representation of the IPv4 address given
// byte per byte, most significant bytes first.
BRILLO_EXPORT constexpr uint32_t Ipv4Addr(uint8_t b0,
                                          uint8_t b1,
                                          uint8_t b2,
                                          uint8_t b3) {
  return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

// Returns the netmask in network byte order given a prefixl length.
BRILLO_EXPORT uint32_t Ipv4Netmask(uint32_t prefix_len);

// Returns the broadcast address in network byte order for the subnet provided.
BRILLO_EXPORT uint32_t Ipv4BroadcastAddr(uint32_t base, uint32_t prefix_len);

// Returns the literal representation of the IPv4 address given in network byte
// order.
BRILLO_EXPORT std::string IPv4AddressToString(uint32_t addr);

// Returns the literal representation of the IPv6 address given.
BRILLO_EXPORT std::string IPv6AddressToString(const struct in6_addr& addr);

// Returns the IPv6 address struct of the IPv6 address string given.
BRILLO_EXPORT struct in6_addr StringToIPv6Address(const std::string& buf);

// Returns the CIDR representation of an IPv4 address given in network byte
// order.
BRILLO_EXPORT std::string IPv4AddressToCidrString(uint32_t addr,
                                                  uint32_t prefix_length);

// Returns a string representation of MAC address given.
BRILLO_EXPORT std::string MacAddressToString(const MacAddress& addr);

// Returns true if the prefix between the two IPv6 addresses is equal.
BRILLO_EXPORT bool IsIPv6PrefixEqual(const struct in6_addr& a,
                                     const struct in6_addr& b,
                                     int prefix_length);

BRILLO_EXPORT bool FindFirstIPv6Address(const std::string& ifname,
                                        struct in6_addr* address);

BRILLO_EXPORT bool GenerateRandomIPv6Prefix(struct in6_addr* prefix, int len);

BRILLO_EXPORT bool GenerateEUI64Address(in6_addr* address,
                                        const in6_addr& prefix,
                                        const MacAddress& mac);

BRILLO_EXPORT void SetSockaddrIn(struct sockaddr* sockaddr, uint32_t addr);

BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct in_addr& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct in6_addr& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr_storage& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr_in& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr_in6& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr_un& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr_vm& addr);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct sockaddr_ll& addr);

BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const struct rtentry& route);

// Fold 32-bit into 16 bits.
BRILLO_EXPORT uint16_t FoldChecksum(uint32_t sum);

// RFC 1071: We are doing calculation directly in network order.
// Note this algorithm works regardless of the endianness of the host.
BRILLO_EXPORT uint32_t NetChecksum(const void* data, ssize_t len);

BRILLO_EXPORT uint16_t Ipv4Checksum(const iphdr* ip);

// UDPv4 checksum along with IPv4 pseudo-header is defined in RFC 793,
// Section 3.1.
BRILLO_EXPORT uint16_t Udpv4Checksum(const uint8_t* udp_packet, ssize_t len);

// ICMPv6 checksum is defined in RFC 8200 Section 8.1
BRILLO_EXPORT uint16_t Icmpv6Checksum(const uint8_t* icmp6_packet, ssize_t len);

// Returns true if multicast forwarding should be enabled for this interface.
BRILLO_EXPORT bool IsMulticastInterface(const std::string& ifname);

// Returns the IP family from the string |ip_address|. If |ip_address| is
// invalid, returns AF_UNSPEC (0).
BRILLO_EXPORT sa_family_t GetIpFamily(const std::string& ip_address);

}  // namespace patchpanel

#endif  // PATCHPANEL_NET_UTIL_H_
