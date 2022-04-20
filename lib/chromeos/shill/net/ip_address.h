// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_IP_ADDRESS_H_
#define SHILL_NET_IP_ADDRESS_H_

#include <netinet/in.h>

#include <string>
#include <utility>

#include "shill/net/byte_string.h"
#include "shill/net/shill_export.h"

namespace shill {

// Class to represent an IP address, whether v4 or v6.
// Is both copyable and movable.
class SHILL_EXPORT IPAddress {
 public:
  using Family = unsigned char;
  static constexpr Family kFamilyUnknown = AF_UNSPEC;
  static constexpr Family kFamilyIPv4 = AF_INET;
  static constexpr Family kFamilyIPv6 = AF_INET6;
  static const char kFamilyNameUnknown[];
  static const char kFamilyNameIPv4[];
  static const char kFamilyNameIPv6[];

  IPAddress();

  explicit IPAddress(Family family);
  IPAddress(Family family, const ByteString& address);
  IPAddress(Family family, const ByteString& address, unsigned int prefix);

  // Constructs an IPAddress object given a standard string representation of an
  // IP address (e.g. "192.144.30.54").
  explicit IPAddress(const std::string& ip_string);
  IPAddress(const std::string& ip_string, unsigned int prefix);

  // Constructs an IPAddress object from a sockaddr_in or sockaddr_in6
  // structure, depending on the family specified in |address_struct|.  |size|
  // specifies the actual size of the structure backing |address_struct|.
  IPAddress(const sockaddr* address_struct, size_t size);

  ~IPAddress();

  IPAddress(const IPAddress& b) = default;
  IPAddress(IPAddress&& b)
      : family_(b.family_),
        address_(std::move(b.address_)),
        prefix_(b.prefix_) {
    b.family_ = kFamilyUnknown;
  }

  IPAddress& operator=(const IPAddress& b) = default;
  IPAddress& operator=(IPAddress&& b) {
    if (this != &b) {
      family_ = b.family_;
      b.family_ = kFamilyUnknown;
      address_ = std::move(b.address_);
      prefix_ = b.prefix_;
    }
    return *this;
  }

  // Static utilities
  // Get the length in bytes of addresses of the given family
  static size_t GetAddressLength(Family family);

  // Returns the maximum prefix length for address family |family|, i.e.,
  // the length of this address type in bits.
  static size_t GetMaxPrefixLength(Family family);

  // Returns the prefix length given an address |family| and a |mask|. For
  // example, returns 24 for an IPv4 mask 255.255.255.0.
  static size_t GetPrefixLengthFromMask(Family family, const std::string& mask);

  // Returns an IPAddress of type |family| that has all the high-order |prefix|
  // bits set.
  static IPAddress GetAddressMaskFromPrefix(Family family, size_t prefix);

  // Returns the name of an address family.
  static std::string GetAddressFamilyName(Family family);

  // Getters and Setters
  Family family() const { return family_; }
  void set_family(Family family) { family_ = family; }
  const ByteString& address() const { return address_; }
  unsigned int prefix() const { return prefix_; }
  void set_prefix(unsigned int prefix) { prefix_ = prefix; }
  const unsigned char* GetConstData() const { return address_.GetConstData(); }
  size_t GetLength() const { return address_.GetLength(); }
  bool IsDefault() const { return address_.IsZero() && !prefix_; }
  bool IsValid() const {
    return family_ != kFamilyUnknown &&
           GetLength() == GetAddressLength(family_);
  }

  // Parse an IP address string.
  bool SetAddressFromString(const std::string& address_string);
  // Parse an "address/prefix" IP address and prefix pair from a string.
  bool SetAddressAndPrefixFromString(const std::string& address_string);
  // An uninitialized IPAddress is empty and invalid when constructed.
  // Use SetAddressToDefault() to set it to the default or "all-zeroes" address.
  void SetAddressToDefault();
  // Return the string equivalent of the address.  Returns true if the
  // conversion succeeds in which case |address_string| is set to the
  // result.  Otherwise the function returns false and |address_string|
  // is left unmodified.
  bool IntoString(std::string* address_string) const;
  // Similar to IntoString, but returns by value. Convenient for logging.
  std::string ToString() const;
  // Places |address.ToString| onto the output stream.
  friend std::ostream& operator<<(std::ostream& os, const IPAddress address) {
    os << address.ToString();
    return os;
  }

  // Populates the address and family portion of a sockaddr_in or
  // sockaddr_in6 structure, depending on the IPAddress family.  Returns true
  // if the specified |size| is large enough to accommodate the address family,
  // and a valid address and family are written to the structure.  Otherwise,
  // false is returned and the memory at |address_struct| is unmodified.
  bool IntoSockAddr(sockaddr* address_struct, size_t size) const;

  // Returns whether |b| has the same family, address and prefix as |this|.
  bool Equals(const IPAddress& b) const;

  bool operator==(const IPAddress& b) const { return Equals(b); }
  bool operator!=(const IPAddress& b) const { return !Equals(b); }

  // Returns whether |b| has the same family and address as |this|.
  bool HasSameAddressAs(const IPAddress& b) const;

  // Perform an AND operation between the address data of |this| and that
  // of |b|.  Returns an IPAddress containing the result of the operation.
  // It is an error if |this| and |b| are not of the same address family
  // or if either are not valid,
  IPAddress MaskWith(const IPAddress& b) const;

  // Perform an OR operation between the address data of |this| and that
  // of |b|.  Returns an IPAddress containing the result of the operation.
  // It is an error if |this| and |b| are not of the same address family
  // or if either are not valid,
  IPAddress MergeWith(const IPAddress& b) const;

  // Return an address that represents the network-part of the address,
  // i.e, the address with all but the prefix bits masked out.
  IPAddress GetNetworkPart() const;

  // Return the default broadcast address for the IP address, by setting
  // all of the host-part bits to 1.
  IPAddress GetDefaultBroadcast();

  // Tests whether this IPAddress is able to directly access the address
  // |b| without an intervening gateway.  It tests whether the network
  // part of |b| is the same as the network part of |this|, using the
  // prefix of |this|.  Returns true if |b| is reachable, false otherwise.
  bool CanReachAddress(const IPAddress& b) const;

  // Compares the byte value of this IPAddress with the byte value of
  // |b|.  This is used for allow binary search on IP addresses of the
  // same type.
  bool operator<(const IPAddress& b) const;

 private:
  Family family_;
  ByteString address_;
  unsigned int prefix_;
};

}  // namespace shill

#endif  // SHILL_NET_IP_ADDRESS_H_
