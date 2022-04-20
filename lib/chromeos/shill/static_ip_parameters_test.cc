// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/static_ip_parameters.h"

//#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/ipconfig.h"
#include "shill/mock_control.h"
#include "shill/mock_ipconfig.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {

const char kAddress[] = "10.0.0.1";
const char kGateway[] = "10.0.0.254";
const int32_t kMtu = 512;

const char kNameServer0[] = "10.0.1.253";
const char kNameServer1[] = "10.0.1.252";
const char kNameServers[] = "10.0.1.253,10.0.1.252";

const char kSearchDomains[] = "example.com,chromium.org";
const char kSearchDomain0[] = "example.com";
const char kSearchDomain1[] = "chromium.org";

const char kPeerAddress[] = "10.0.0.2";
const int32_t kPrefixLen = 24;

const char kExcludedRoutes[] = "192.168.1.0/24,192.168.2.0/24";
const char kExcludedRoute0[] = "192.168.1.0/24";
const char kExcludedRoute1[] = "192.168.2.0/24";

const char kIncludedRoutes[] = "0.0.0.0/0";
const IPConfig::Route kIncludedRoute0("0.0.0.0", 0, "10.0.0.254");

}  // namespace

class StaticIPParametersTest : public Test {
 public:
  StaticIPParametersTest() = default;

  void ExpectEmptyIPConfig() {
    EXPECT_TRUE(ipconfig_props_.address.empty());
    EXPECT_TRUE(ipconfig_props_.gateway.empty());
    EXPECT_EQ(IPConfig::kUndefinedMTU, ipconfig_props_.mtu);
    EXPECT_TRUE(ipconfig_props_.dns_servers.empty());
    EXPECT_TRUE(ipconfig_props_.domain_search.empty());
    EXPECT_TRUE(ipconfig_props_.peer_address.empty());
    EXPECT_FALSE(ipconfig_props_.subnet_prefix);
    EXPECT_TRUE(ipconfig_props_.exclusion_list.empty());
    EXPECT_TRUE(ipconfig_props_.routes.empty());
    EXPECT_TRUE(ipconfig_props_.default_route);
  }
  // Modify an IP address string in some predictable way.  There's no need
  // for the output string to be valid from a networking perspective.
  std::string VersionedAddress(const std::string& address, int version) {
    std::string returned_address = address;
    CHECK(returned_address.length());
    returned_address[returned_address.length() - 1] += version;
    return returned_address;
  }
  void ExpectPopulatedIPConfigWithVersion(int version) {
    EXPECT_EQ(VersionedAddress(kAddress, version), ipconfig_props_.address);
    EXPECT_EQ(VersionedAddress(kGateway, version), ipconfig_props_.gateway);
    EXPECT_EQ(kMtu + version, ipconfig_props_.mtu);

    EXPECT_EQ(2, ipconfig_props_.dns_servers.size());
    EXPECT_EQ(VersionedAddress(kNameServer0, version),
              ipconfig_props_.dns_servers[0]);
    EXPECT_EQ(VersionedAddress(kNameServer1, version),
              ipconfig_props_.dns_servers[1]);

    // VersionedAddress() increments the final character of each domain
    // name.
    EXPECT_EQ(2, ipconfig_props_.domain_search.size());
    EXPECT_EQ(VersionedAddress(kSearchDomain0, version),
              ipconfig_props_.domain_search[0]);
    EXPECT_EQ(VersionedAddress(kSearchDomain1, version),
              ipconfig_props_.domain_search[1]);

    EXPECT_EQ(VersionedAddress(kPeerAddress, version),
              ipconfig_props_.peer_address);
    EXPECT_EQ(kPrefixLen + version, ipconfig_props_.subnet_prefix);

    EXPECT_EQ(2, ipconfig_props_.exclusion_list.size());
    EXPECT_EQ(VersionedAddress(kExcludedRoute0, version),
              ipconfig_props_.exclusion_list[0]);
    EXPECT_EQ(VersionedAddress(kExcludedRoute1, version),
              ipconfig_props_.exclusion_list[1]);

    // VersionedAddress() increments the final digit of the prefix on
    // the IncludedRoutes property, and the final digit of the IP address
    // on the Gateway property.
    EXPECT_EQ(1, ipconfig_props_.routes.size());
    EXPECT_EQ(kIncludedRoute0.host, ipconfig_props_.routes[0].host);
    EXPECT_EQ(kIncludedRoute0.prefix + version,
              ipconfig_props_.routes[0].prefix);
    EXPECT_EQ(VersionedAddress(kIncludedRoute0.gateway, version),
              ipconfig_props_.routes[0].gateway);
    EXPECT_FALSE(ipconfig_props_.default_route);
  }
  void ExpectPopulatedIPConfig() { ExpectPopulatedIPConfigWithVersion(0); }
  void ExpectPropertiesWithVersion(PropertyStore* store,
                                   const std::string& property_prefix,
                                   int version) {
    KeyValueStore args;
    Error unused_error;
    EXPECT_TRUE(store->GetKeyValueStoreProperty(property_prefix + "Config",
                                                &args, &unused_error));
    EXPECT_EQ(VersionedAddress(kAddress, version),
              args.Get<std::string>(kAddressProperty));
    EXPECT_EQ(VersionedAddress(kGateway, version),
              args.Get<std::string>(kGatewayProperty));
    EXPECT_EQ(kMtu + version, args.Get<int32_t>(kMtuProperty));
    std::vector<std::string> kTestNameServers(
        {VersionedAddress(kNameServer0, version),
         VersionedAddress(kNameServer1, version)});
    EXPECT_EQ(kTestNameServers, args.Get<Strings>(kNameServersProperty));
    std::vector<std::string> kTestSearchDomains(
        {VersionedAddress(kSearchDomain0, version),
         VersionedAddress(kSearchDomain1, version)});
    EXPECT_EQ(kTestSearchDomains, args.Get<Strings>(kSearchDomainsProperty));
    EXPECT_EQ(VersionedAddress(kPeerAddress, version),
              args.Get<std::string>(kPeerAddressProperty));
    EXPECT_EQ(kPrefixLen + version, args.Get<int32_t>(kPrefixlenProperty));
    std::vector<std::string> kTestExcludedRoutes(
        {VersionedAddress(kExcludedRoute0, version),
         VersionedAddress(kExcludedRoute1, version)});
    EXPECT_EQ(kTestExcludedRoutes, args.Get<Strings>(kExcludedRoutesProperty));
    std::vector<std::string> kTestIncludedRoutes(
        {VersionedAddress(kIncludedRoutes, version)});
    EXPECT_EQ(kTestIncludedRoutes, args.Get<Strings>(kIncludedRoutesProperty));
  }
  void ExpectProperties(PropertyStore* store,
                        const std::string& property_prefix) {
    ExpectPropertiesWithVersion(store, property_prefix, 0);
  }
  void PopulateIPConfig() {
    ipconfig_props_.address = kAddress;
    ipconfig_props_.gateway = kGateway;
    ipconfig_props_.mtu = kMtu;
    ipconfig_props_.dns_servers = {kNameServer0, kNameServer1};
    ipconfig_props_.domain_search = {kSearchDomain0, kSearchDomain1};
    ipconfig_props_.peer_address = kPeerAddress;
    ipconfig_props_.subnet_prefix = kPrefixLen;
    ipconfig_props_.exclusion_list = {kExcludedRoute0, kExcludedRoute1};
    ipconfig_props_.routes = {kIncludedRoute0};
    ipconfig_props_.default_route = false;
  }
  void SetStaticProperties(PropertyStore* store) {
    SetStaticPropertiesWithVersion(store, 0);
  }
  void SetStaticPropertiesWithVersion(PropertyStore* store, int version) {
    KeyValueStore args;
    args.Set<std::string>(kAddressProperty,
                          VersionedAddress(kAddress, version));
    args.Set<std::string>(kGatewayProperty,
                          VersionedAddress(kGateway, version));
    args.Set<int32_t>(kMtuProperty, kMtu + version);
    args.Set<Strings>(kNameServersProperty,
                      {VersionedAddress(kNameServer0, version),
                       VersionedAddress(kNameServer1, version)});
    args.Set<Strings>(kSearchDomainsProperty,
                      {VersionedAddress(kSearchDomain0, version),
                       VersionedAddress(kSearchDomain1, version)});
    args.Set<std::string>(kPeerAddressProperty,
                          VersionedAddress(kPeerAddress, version));
    args.Set<int32_t>(kPrefixlenProperty, kPrefixLen + version);
    args.Set<Strings>(kExcludedRoutesProperty,
                      {VersionedAddress(kExcludedRoute0, version),
                       VersionedAddress(kExcludedRoute1, version)});
    args.Set<Strings>(kIncludedRoutesProperty,
                      {VersionedAddress(kIncludedRoutes, version)});

    Error error;
    store->SetKeyValueStoreProperty(kStaticIPConfigProperty, args, &error);
  }
  void SetStaticPropertiesWithoutRoute(PropertyStore* store) {
    KeyValueStore args;
    args.Set<std::string>(kAddressProperty, kAddress);
    args.Set<std::string>(kGatewayProperty, kGateway);
    args.Set<int32_t>(kMtuProperty, kMtu);
    Error error;
    store->SetKeyValueStoreProperty(kStaticIPConfigProperty, args, &error);
  }
  KeyValueStore* static_args() { return &static_params_.args_; }
  KeyValueStore* saved_args() { return &static_params_.saved_args_; }

 protected:
  StaticIPParameters static_params_;
  IPConfig::Properties ipconfig_props_;
};

TEST_F(StaticIPParametersTest, InitState) {
  ExpectEmptyIPConfig();

  // Applying an empty set of parameters on an empty set of properties should
  // be a no-op.
  static_params_.ApplyTo(&ipconfig_props_);
  ExpectEmptyIPConfig();
}

TEST_F(StaticIPParametersTest, ApplyEmptyParameters) {
  PopulateIPConfig();
  static_params_.ApplyTo(&ipconfig_props_);
  ExpectPopulatedIPConfig();
}

TEST_F(StaticIPParametersTest, DefaultRoute) {
  IPConfig::Properties props;
  PropertyStore store;
  static_params_.PlumbPropertyStore(&store);
  SetStaticPropertiesWithoutRoute(&store);
  static_params_.ApplyTo(&props);
  EXPECT_TRUE(props.default_route);
  SetStaticProperties(&store);
  static_params_.ApplyTo(&props);
  EXPECT_FALSE(props.default_route);
}

TEST_F(StaticIPParametersTest, ControlInterface) {
  PropertyStore store;
  int version = 0;
  static_params_.PlumbPropertyStore(&store);
  SetStaticProperties(&store);
  static_params_.ApplyTo(&ipconfig_props_);
  ExpectPopulatedIPConfig();

  EXPECT_TRUE(static_params_.ContainsAddress());
  EXPECT_TRUE(store.Contains("StaticIPConfig"));
  static_args()->Remove("Address");
  EXPECT_FALSE(static_params_.ContainsAddress());
  static_args()->Remove("Mtu");
  IPConfig::Properties props;
  const std::string kTestAddress("test_address");
  props.address = kTestAddress;
  const int32_t kTestMtu = 256;
  props.mtu = kTestMtu;
  static_params_.ApplyTo(&props);
  EXPECT_EQ(kTestAddress, props.address);
  EXPECT_EQ(kTestMtu, props.mtu);

  EXPECT_FALSE(static_args()->Contains<std::string>("Address"));
  EXPECT_EQ(kGateway, static_args()->Get<std::string>("Gateway"));
  EXPECT_FALSE(static_args()->Contains<int32_t>("Mtu"));
  std::vector<std::string> kTestNameServers(
      {VersionedAddress(kNameServer0, version),
       VersionedAddress(kNameServer1, version)});
  EXPECT_EQ(kTestNameServers, static_args()->Get<Strings>("NameServers"));
  std::vector<std::string> kTestSearchDomains(
      {VersionedAddress(kSearchDomain0, version),
       VersionedAddress(kSearchDomain1, version)});
  EXPECT_EQ(kTestSearchDomains, static_args()->Get<Strings>("SearchDomains"));
  EXPECT_EQ(VersionedAddress(kPeerAddress, version),
            static_args()->Get<std::string>("PeerAddress"));
  EXPECT_EQ(kPrefixLen + version, static_args()->Get<int32_t>("Prefixlen"));
  std::vector<std::string> kTestExcludedRoutes(
      {VersionedAddress(kExcludedRoute0, version),
       VersionedAddress(kExcludedRoute1, version)});
  EXPECT_EQ(kTestExcludedRoutes, static_args()->Get<Strings>("ExcludedRoutes"));
  std::vector<std::string> kTestIncludedRoutes(
      {VersionedAddress(kIncludedRoutes, version)});
  EXPECT_EQ(kTestIncludedRoutes, static_args()->Get<Strings>("IncludedRoutes"));
}

TEST_F(StaticIPParametersTest, Profile) {
  FakeStore store;
  const std::string kID = "storage_id";
  store.SetString(kID, "StaticIP.Address", kAddress);
  store.SetString(kID, "StaticIP.Gateway", kGateway);
  store.SetInt(kID, "StaticIP.Mtu", kMtu);
  store.SetString(kID, "StaticIP.NameServers", kNameServers);
  store.SetString(kID, "StaticIP.SearchDomains", kSearchDomains);
  store.SetString(kID, "StaticIP.PeerAddress", kPeerAddress);
  store.SetInt(kID, "StaticIP.Prefixlen", kPrefixLen);
  store.SetString(kID, "StaticIP.ExcludedRoutes", kExcludedRoutes);
  store.SetString(kID, "StaticIP.IncludedRoutes", kIncludedRoutes);

  static_params_.Load(&store, kID);
  static_params_.ApplyTo(&ipconfig_props_);
  ExpectPopulatedIPConfig();

  static_params_.Save(&store, kID);

  std::string address;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.Address", &address));
  EXPECT_EQ(address, kAddress);
  std::string gateway;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.Gateway", &gateway));
  EXPECT_EQ(gateway, kGateway);
  int mtu;
  EXPECT_TRUE(store.GetInt(kID, "StaticIP.Mtu", &mtu));
  EXPECT_EQ(mtu, kMtu);
  std::string nameservers;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.NameServers", &nameservers));
  EXPECT_EQ(nameservers, kNameServers);
  std::string searchdomains;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.SearchDomains", &searchdomains));
  EXPECT_EQ(searchdomains, kSearchDomains);
  std::string peeraddress;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.PeerAddress", &peeraddress));
  EXPECT_EQ(peeraddress, kPeerAddress);
  int prefixlen;
  EXPECT_TRUE(store.GetInt(kID, "StaticIP.Prefixlen", &prefixlen));
  EXPECT_EQ(prefixlen, kPrefixLen);
  std::string excludedroutes;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.ExcludedRoutes", &excludedroutes));
  EXPECT_EQ(excludedroutes, kExcludedRoutes);
  std::string includedroutes;
  EXPECT_TRUE(store.GetString(kID, "StaticIP.IncludedRoutes", &includedroutes));
  EXPECT_EQ(includedroutes, kIncludedRoutes);
}

TEST_F(StaticIPParametersTest, SavedParameters) {
  // Calling RestoreTo() when no parameters are set should not crash or
  // add any entries.
  static_params_.RestoreTo(&ipconfig_props_);
  ExpectEmptyIPConfig();

  PopulateIPConfig();
  PropertyStore static_params_props;
  static_params_.PlumbPropertyStore(&static_params_props);
  SetStaticPropertiesWithVersion(&static_params_props, 1);
  static_params_.ApplyTo(&ipconfig_props_);

  // The version 0 properties in |ipconfig_props_| are now in SavedIP.*
  // properties, while the version 1 StaticIP parameters are now in
  // |ipconfig_props_|.
  ExpectPropertiesWithVersion(&static_params_props, "SavedIP", 0);
  ExpectPopulatedIPConfigWithVersion(1);

  // Clear all "StaticIP" parameters.
  static_args()->Clear();

  // Another ApplyTo() call rotates the version 1 properties in
  // |ipconfig_props_| over to SavedIP.*.  Since there are no StaticIP
  // parameters, |ipconfig_props_| should remain populated with version 1
  // parameters.
  static_params_.ApplyTo(&ipconfig_props_);
  ExpectPropertiesWithVersion(&static_params_props, "SavedIP", 1);
  ExpectPopulatedIPConfigWithVersion(1);

  // Reset |ipconfig_props_| to version 0.
  PopulateIPConfig();

  // A RestoreTo() call moves the version 1 "SavedIP" parameters into
  // |ipconfig_props_|.
  SetStaticPropertiesWithVersion(&static_params_props, 2);
  static_params_.RestoreTo(&ipconfig_props_);
  ExpectPopulatedIPConfigWithVersion(1);

  // All "SavedIP" parameters should be cleared.
  EXPECT_TRUE(saved_args()->IsEmpty());

  // Static IP parameters should be unchanged.
  ExpectPropertiesWithVersion(&static_params_props, "StaticIP", 2);
}

}  // namespace shill
