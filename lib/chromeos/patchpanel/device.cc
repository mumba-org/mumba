// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/device.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <utility>

#include <base/bind.h>
//#include <base/check.h>
#include <base/lazy_instance.h>
#include <base/logging.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

Device::Config::Config(const MacAddress& mac_addr,
                       std::unique_ptr<Subnet> ipv4_subnet,
                       std::unique_ptr<SubnetAddress> host_ipv4_addr,
                       std::unique_ptr<SubnetAddress> guest_ipv4_addr,
                       std::unique_ptr<Subnet> lxd_ipv4_subnet)
    : mac_addr_(mac_addr),
      ipv4_subnet_(std::move(ipv4_subnet)),
      host_ipv4_addr_(std::move(host_ipv4_addr)),
      guest_ipv4_addr_(std::move(guest_ipv4_addr)),
      lxd_ipv4_subnet_(std::move(lxd_ipv4_subnet)) {}

Device::Device(GuestType type,
               const std::string& phys_ifname,
               const std::string& host_ifname,
               const std::string& guest_ifname,
               std::unique_ptr<Device::Config> config)
    : type_(type),
      phys_ifname_(phys_ifname),
      host_ifname_(host_ifname),
      guest_ifname_(guest_ifname),
      config_(std::move(config)) {
  DCHECK(config_);
}

Device::Config& Device::config() const {
  CHECK(config_);
  return *config_.get();
}

void Device::Config::set_tap_ifname(const std::string& tap_ifname) {
  tap_ = tap_ifname;
}

const std::string& Device::Config::tap_ifname() const {
  return tap_;
}

std::unique_ptr<Device::Config> Device::release_config() {
  return std::move(config_);
}

std::ostream& operator<<(std::ostream& stream, const Device& device) {
  stream << "{ type: " << device.type() << ", ifname: " << device.phys_ifname()
         << ", bridge_ifname: " << device.host_ifname()
         << ", bridge_ipv4_addr: "
         << device.config().host_ipv4_subnet_addr()->ToCidrString()
         << ", guest_ifname: " << device.guest_ifname() << ", guest_ipv4_addr: "
         << device.config().guest_ipv4_subnet_addr()->ToCidrString()
         << ", guest_mac_addr: "
         << MacAddressToString(device.config().mac_addr())
         << ", tap_ifname: " << device.config().tap_ifname() << '}';
  return stream;
}

}  // namespace patchpanel
