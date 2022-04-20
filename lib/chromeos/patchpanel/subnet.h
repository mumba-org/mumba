// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SUBNET_H_
#define PATCHPANEL_SUBNET_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>

namespace patchpanel {

// Represents an allocated address inside an IPv4 subnet.  The address is freed
// when this object is destroyed.
class BRILLO_EXPORT SubnetAddress {
 public:
  // Creates a new SubnetAddress with the given base address and prefix length.
  // |base_addr| must be in network-byte order. |release_cb| runs in the
  // destructor of this class and can be used to free other resources associated
  // with the subnet address.
  SubnetAddress(uint32_t addr,
                uint32_t prefix_length,
                base::OnceClosure release_cb);
  SubnetAddress(const SubnetAddress&) = delete;
  SubnetAddress& operator=(const SubnetAddress&) = delete;

  ~SubnetAddress();

  // Returns this address in network-byte order.
  uint32_t Address() const;

  // Returns the CIDR representation of this address, for instance
  // 192.168.0.34/24.
  std::string ToCidrString() const;

  // Returns the IPv4 literal representation of this address, for instance
  // 192.168.0.34.
  std::string ToIPv4String() const;

  // Returns the subnet etmask in network-byte order.
  uint32_t Netmask() const;

 private:
  // The address in network-byte order.
  uint32_t addr_;
  // The prefix length of the address.
  uint32_t prefix_length_;

  // Callback to run when this object is destroyed.
  base::OnceClosure release_cb_;
};

// Represents an allocated IPv4 subnet.
class BRILLO_EXPORT Subnet {
 public:
  // Creates a new Subnet with the given base address and prefix length.
  // |base_addr| must be in network-byte order. |release_cb| runs in the
  // destructor of this class and can be used to free other resources associated
  // with the subnet.
  Subnet(uint32_t base_addr,
         uint32_t prefix_length,
         base::OnceClosure release_cb);
  Subnet(const Subnet&) = delete;
  Subnet& operator=(const Subnet&) = delete;

  ~Subnet();

  // Marks |addr| as allocated. |addr| must be in network-byte order. Returns
  // nullptr if |addr| has already been allocated or if |addr| is not contained
  // within this subnet. Otherwise, the allocated address is automatically
  // freed when the returned SubnetAddress is destroyed.
  std::unique_ptr<SubnetAddress> Allocate(uint32_t addr);

  // Allocates the address at |offset|. Returns nullptr if |offset| is invalid
  // (exceeds available IPs in the subnet) or is already allocated.
  // |offset| is relative to the first usable host address; e.g. network + 1
  std::unique_ptr<SubnetAddress> AllocateAtOffset(uint32_t offset);

  // Returns the address at the given |offset| in network-byte order. Returns
  // INADDR_ANY if the offset exceeds the available IPs in the subnet.
  // Available IPs do not include the network id or the broadcast address.
  // |offset| is relative to the first usable host address; e.g. network + 1
  uint32_t AddressAtOffset(uint32_t offset) const;

  // Returns the number of available IPs in this subnet.
  uint32_t AvailableCount() const;

  // Returns the base address in network-byte order.
  uint32_t BaseAddress() const;

  // Returns the netmask in network-byte order.
  uint32_t Netmask() const;

  // Returns the prefix in network-byte order.
  uint32_t Prefix() const;

  // Returns the prefix length.
  uint32_t PrefixLength() const;

  // Returns the CIDR representation of this subnet, for instance
  // 192.168.0.0/24.
  std::string ToCidrString() const;

 private:
  // Marks the address at |offset| as free.
  void Free(uint32_t offset);

  // Base address of the subnet, in network-byte order.
  uint32_t base_addr_;

  // Prefix length.
  uint32_t prefix_length_;

  // Keeps track of allocated addresses.
  std::vector<bool> addrs_;

  // Callback to run when this object is deleted.
  base::OnceClosure release_cb_;

  base::WeakPtrFactory<Subnet> weak_factory_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_SUBNET_H_
