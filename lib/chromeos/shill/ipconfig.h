// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_IPCONFIG_H_
#define SHILL_IPCONFIG_H_

#include <memory>
#include <string>
#include <vector>

#include <base/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/mockable.h"
#include "shill/net/ip_address.h"
#include "shill/refptr_types.h"
#include "shill/routing_policy_entry.h"
#include "shill/store/property_store.h"

namespace shill {
class ControlInterface;
class Error;
class IPConfigAdaptorInterface;
class StaticIPParameters;
class Time;

// IPConfig superclass. Individual IP configuration types will inherit from this
// class.
class IPConfig : public base::RefCounted<IPConfig> {
 public:
  struct Route {
    Route() : prefix(0) {}
    Route(const std::string& host_in,
          int prefix_in,
          const std::string& gateway_in)
        : host(host_in), prefix(prefix_in), gateway(gateway_in) {}
    std::string host;
    int prefix;
    std::string gateway;
  };

  struct Properties {
    Properties()
        : address_family(IPAddress::kFamilyUnknown),
          subnet_prefix(0),
          default_route(true),
          blackhole_ipv6(false),
          use_if_addrs(false),
          mtu(kUndefinedMTU),
          lease_duration_seconds(0) {}

    IPAddress::Family address_family;
    std::string address;
    int32_t subnet_prefix;
    std::string broadcast_address;
    std::vector<std::string> dns_servers;
    std::string domain_name;
    std::string accepted_hostname;
    std::vector<std::string> domain_search;
    std::string gateway;
    std::string method;
    // The address of the remote endpoint for pointopoint interfaces.
    // Note that presense of this field indicates that this is a p2p interface,
    // and a gateway won't be needed in creating routes on this interface.
    std::string peer_address;
    // Any egress traffic sent to prefixes listed in |included_dsts| will be
    // routed through this connection, even if it is not the default connection.
    std::vector<IPAddress> included_dsts;
    // List of uids that have their traffic blocked.
    std::vector<uint32_t> blackholed_uids;
    // Set the flag to true when the interface should be set as the default
    // route.
    bool default_route;
    // A list of IP blocks in CIDR format that should be excluded from VPN.
    std::vector<std::string> exclusion_list;
    // Block IPv6 traffic.  Used if connected to an IPv4-only VPN.
    bool blackhole_ipv6;
    // Should traffic whose source address matches one of this interface's
    // addresses be sent to the interface's per-device table. This field is only
    // used for non-physical interfaces--physical interfaces will always act as
    // if this were true.
    bool use_if_addrs;
    // MTU to set on the interface.  If unset, defaults to |kDefaultMTU|.
    int32_t mtu;
    // A list of (host,prefix,gateway) tuples for this connection.
    std::vector<Route> routes;
    // Vendor encapsulated option string gained from DHCP.
    ByteArray vendor_encapsulated_options;
    // iSNS option data gained from DHCP.
    ByteArray isns_option_data;
    // Web Proxy Auto Discovery (WPAD) URL gained from DHCP.
    std::string web_proxy_auto_discovery;
    // Length of time the lease was granted.
    uint32_t lease_duration_seconds;
  };

  enum Method { kMethodUnknown, kMethodPPP, kMethodStatic, kMethodDHCP };

  // Define a default and a minimum viable MTU value.
  static const int kDefaultMTU;
  static const int kMinIPv4MTU;
  static const int kMinIPv6MTU;
  static const int kUndefinedMTU;

  static constexpr char kTypeDHCP[] = "dhcp";

  IPConfig(ControlInterface* control_interface, const std::string& device_name);
  IPConfig(ControlInterface* control_interface,
           const std::string& device_name,
           const std::string& type);
  IPConfig(const IPConfig&) = delete;
  IPConfig& operator=(const IPConfig&) = delete;

  virtual ~IPConfig();

  const std::string& device_name() const { return device_name_; }
  const std::string& type() const { return type_; }
  uint32_t serial() const { return serial_; }

  const RpcIdentifier& GetRpcIdentifier() const;

  void set_properties(const Properties& props) { properties_ = props; }
  mockable const Properties& properties() const { return properties_; }

  // Update DNS servers setting for this ipconfig, this allows Chrome
  // to retrieve the new DNS servers.
  mockable void UpdateDNSServers(std::vector<std::string> dns_servers);

  // Reset the IPConfig properties to their default values.
  mockable void ResetProperties();

  // Updates the IP configuration properties and notifies listeners on D-Bus.
  void UpdateProperties(const Properties& properties);

  PropertyStore* mutable_store() { return &store_; }
  const PropertyStore& store() const { return store_; }
  void ApplyStaticIPParameters(StaticIPParameters* static_ip_parameters);

  // Restore the fields of |properties_| to their original values before
  // static IP parameters were previously applied.
  void RestoreSavedIPParameters(StaticIPParameters* static_ip_parameters);

  // Returns whether the function call changed the configuration.
  bool SetBlackholedUids(const std::vector<uint32_t>& uids);
  bool ClearBlackholedUids();

 private:
  friend class IPConfigAdaptorInterface;
  friend class IPConfigTest;
  friend class ConnectionTest;

  FRIEND_TEST(DeviceTest, DestroyIPConfig);
  FRIEND_TEST(DeviceTest, IsConnectedViaTether);
  FRIEND_TEST(DeviceTest, OnIPConfigExpired);
  FRIEND_TEST(IPConfigTest, UpdateProperties);
  FRIEND_TEST(ResolverTest, Empty);
  FRIEND_TEST(ResolverTest, NonEmpty);
  FRIEND_TEST(RoutingTableTest, RouteAddDelete);

  static const char kType[];

  // Inform RPC listeners of changes to our properties. MAY emit
  // changes even on unchanged properties.
  mockable void EmitChanges();

  static uint32_t global_serial_;
  PropertyStore store_;
  const std::string device_name_;
  const std::string type_;
  const uint32_t serial_;
  std::unique_ptr<IPConfigAdaptorInterface> adaptor_;
  Properties properties_;
  base::WeakPtrFactory<IPConfig> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_IPCONFIG_H_
