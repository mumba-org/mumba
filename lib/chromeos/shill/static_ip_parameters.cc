// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/static_ip_parameters.h"

#include <string.h>

#include <string>
#include <vector>

#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/net/ip_address.h"
#include "shill/store/property_accessor.h"
#include "shill/store/property_store.h"
#include "shill/store/store_interface.h"

namespace shill {

// static
const char StaticIPParameters::kConfigKeyPrefix[] = "StaticIP.";
// static
const char StaticIPParameters::kSavedConfigKeyPrefix[] = "SavedIP.";
// static
const StaticIPParameters::Property StaticIPParameters::kProperties[] = {
    {kAddressProperty, Property::kTypeString},
    {kGatewayProperty, Property::kTypeString},
    {kMtuProperty, Property::kTypeInt32},
    {kNameServersProperty, Property::kTypeStrings},
    {kSearchDomainsProperty, Property::kTypeStrings},
    {kPeerAddressProperty, Property::kTypeString},
    {kPrefixlenProperty, Property::kTypeInt32},
    {kIncludedRoutesProperty, Property::kTypeStrings},
    {kExcludedRoutesProperty, Property::kTypeStrings},
};

StaticIPParameters::StaticIPParameters() = default;

StaticIPParameters::~StaticIPParameters() = default;

void StaticIPParameters::PlumbPropertyStore(PropertyStore* store) {
  // Register KeyValueStore for both static ip and saved ip parameters.
  store->RegisterDerivedKeyValueStore(
      kSavedIPConfigProperty,
      KeyValueStoreAccessor(
          new CustomAccessor<StaticIPParameters, KeyValueStore>(
              this, &StaticIPParameters::GetSavedIPConfig, nullptr)));
  store->RegisterDerivedKeyValueStore(
      kStaticIPConfigProperty,
      KeyValueStoreAccessor(
          new CustomAccessor<StaticIPParameters, KeyValueStore>(
              this, &StaticIPParameters::GetStaticIPConfig,
              &StaticIPParameters::SetStaticIP)));
}

bool StaticIPParameters::Load(const StoreInterface* storage,
                              const std::string& storage_id) {
  KeyValueStore args;
  for (const auto& property : kProperties) {
    const std::string name(std::string(kConfigKeyPrefix) + property.name);
    switch (property.type) {
      case Property::kTypeInt32: {
        int32_t value;
        if (storage->GetInt(storage_id, name, &value)) {
          args.Set<int32_t>(property.name, value);
        } else {
          args.Remove(property.name);
        }
      } break;
      case Property::kTypeString: {
        std::string value;
        if (storage->GetString(storage_id, name, &value)) {
          args.Set<std::string>(property.name, value);
        } else {
          args.Remove(property.name);
        }
      } break;
      case Property::kTypeStrings: {
        // Name servers field is stored in storage as comma separated string.
        // Keep it as is to be backward compatible.
        std::string value;
        if (storage->GetString(storage_id, name, &value)) {
          std::vector<std::string> string_list = base::SplitString(
              value, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
          args.Set<Strings>(property.name, string_list);
        } else {
          args.Remove(property.name);
        }
      } break;
      default:
        NOTIMPLEMENTED();
        break;
    }
  }
  return SetStaticIP(args, nullptr);
}

void StaticIPParameters::Save(StoreInterface* storage,
                              const std::string& storage_id) {
  for (const auto& property : kProperties) {
    const std::string name(std::string(kConfigKeyPrefix) + property.name);
    bool property_exists = false;
    switch (property.type) {
      case Property::kTypeInt32:
        if (args_.Contains<int32_t>(property.name)) {
          property_exists = true;
          storage->SetInt(storage_id, name, args_.Get<int32_t>(property.name));
        }
        break;
      case Property::kTypeString:
        if (args_.Contains<std::string>(property.name)) {
          property_exists = true;
          storage->SetString(storage_id, name,
                             args_.Get<std::string>(property.name));
        }
        break;
      case Property::kTypeStrings:
        if (args_.Contains<Strings>(property.name)) {
          property_exists = true;
          // Name servers field is stored in storage as comma separated string.
          // Keep it as is to be backward compatible.
          storage->SetString(
              storage_id, name,
              base::JoinString(args_.Get<Strings>(property.name), ","));
        }
        break;
      default:
        NOTIMPLEMENTED();
        break;
    }
    if (!property_exists) {
      storage->DeleteKey(storage_id, name);
    }
  }
}

void StaticIPParameters::ApplyInt(const std::string& property,
                                  int32_t* value_out) {
  saved_args_.Set<int32_t>(property, *value_out);
  if (args_.Contains<int32_t>(property)) {
    *value_out = args_.Get<int32_t>(property);
  }
}

void StaticIPParameters::ApplyString(const std::string& property,
                                     std::string* value_out) {
  saved_args_.Set<std::string>(property, *value_out);
  if (args_.Contains<std::string>(property)) {
    *value_out = args_.Get<std::string>(property);
  }
}

void StaticIPParameters::ApplyStrings(const std::string& property,
                                      std::vector<std::string>* value_out) {
  saved_args_.Set<Strings>(property, *value_out);
  if (args_.Contains<Strings>(property)) {
    *value_out = args_.Get<Strings>(property);
  }
}

void StaticIPParameters::RestoreStrings(const std::string& property,
                                        std::vector<std::string>* value_out) {
  if (saved_args_.Contains<Strings>(property)) {
    *value_out = saved_args_.Get<Strings>(property);
  } else {
    value_out->clear();
  }
}

void StaticIPParameters::ParseRoutes(const std::vector<std::string>& route_list,
                                     const std::string& gateway,
                                     std::vector<IPConfig::Route>* value_out) {
  IPAddress gateway_ip(gateway);
  if (gateway_ip.family() == IPAddress::kFamilyUnknown) {
    return;
  }

  for (const auto& ip : route_list) {
    IPAddress dst_ip(gateway_ip.family());
    if (!dst_ip.SetAddressAndPrefixFromString(ip)) {
      return;
    }

    IPConfig::Route route;
    dst_ip.IntoString(&route.host);
    route.prefix = dst_ip.prefix();
    route.gateway = gateway;
    value_out->push_back(route);
  }
}

void StaticIPParameters::ApplyRoutes(IPConfig::Properties* props) {
  std::vector<std::string> saved_routes;
  for (const auto& route : props->routes) {
    saved_routes.push_back(route.host + "/" +
                           base::NumberToString(route.prefix));
  }
  saved_args_.Set<Strings>(kIncludedRoutesProperty, saved_routes);

  if (!args_.Contains<Strings>(kIncludedRoutesProperty)) {
    return;
  }
  props->routes.clear();
  ParseRoutes(args_.Get<Strings>(kIncludedRoutesProperty), props->gateway,
              &props->routes);
  // Remove default route from the connection if kIncludedRoutesProperty is set.
  props->default_route = false;
}

void StaticIPParameters::RestoreRoutes(IPConfig::Properties* props) {
  props->routes.clear();
  if (saved_args_.Contains<Strings>(kIncludedRoutesProperty)) {
    ParseRoutes(saved_args_.Get<Strings>(kIncludedRoutesProperty),
                props->gateway, &props->routes);
  }
  // TODO(b/184533440): original props->default_route could be lost after Apply
  // -> Restore a StaticIPConfig with IncludedRoutes. This only has an impact
  // when a IPConfig::Refresh is called after applying such a StaticIPConfig,
  // and is temporary since StaticIPConfig is re-applied right after.
}

void StaticIPParameters::ApplyTo(IPConfig::Properties* props) {
  if (props->address_family == IPAddress::kFamilyUnknown) {
    // In situations where no address is supplied (bad or missing DHCP config)
    // supply an address family ourselves.
    // TODO(pstew): Guess from the address values.
    props->address_family = IPAddress::kFamilyIPv4;
  }
  ClearSavedParameters();
  ApplyString(kAddressProperty, &props->address);
  ApplyString(kGatewayProperty, &props->gateway);
  ApplyInt(kMtuProperty, &props->mtu);
  ApplyStrings(kNameServersProperty, &props->dns_servers);
  ApplyStrings(kSearchDomainsProperty, &props->domain_search);
  ApplyString(kPeerAddressProperty, &props->peer_address);
  ApplyInt(kPrefixlenProperty, &props->subnet_prefix);
  ApplyStrings(kExcludedRoutesProperty, &props->exclusion_list);
  ApplyRoutes(props);
}

void StaticIPParameters::RestoreTo(IPConfig::Properties* props) {
  props->address = saved_args_.Lookup<std::string>(kAddressProperty, "");
  props->gateway = saved_args_.Lookup<std::string>(kGatewayProperty, "");
  props->mtu =
      saved_args_.Lookup<int32_t>(kMtuProperty, IPConfig::kUndefinedMTU);
  RestoreStrings(kNameServersProperty, &props->dns_servers);
  RestoreStrings(kSearchDomainsProperty, &props->domain_search);
  props->peer_address =
      saved_args_.Lookup<std::string>(kPeerAddressProperty, "");
  props->subnet_prefix = saved_args_.Lookup<int32_t>(kPrefixlenProperty, 0);
  RestoreStrings(kExcludedRoutesProperty, &props->exclusion_list);
  RestoreRoutes(props);
  ClearSavedParameters();
}

void StaticIPParameters::ClearSavedParameters() {
  saved_args_.Clear();
}

bool StaticIPParameters::ContainsAddress() const {
  return args_.Contains<std::string>(kAddressProperty) &&
         args_.Contains<int32_t>(kPrefixlenProperty);
}

bool StaticIPParameters::ContainsNameServers() const {
  return args_.Contains<Strings>(kNameServersProperty);
}

KeyValueStore StaticIPParameters::GetSavedIPConfig(Error* /*error*/) {
  return saved_args_;
}

KeyValueStore StaticIPParameters::GetStaticIPConfig(Error* /*error*/) {
  return args_;
}

bool StaticIPParameters::SetStaticIP(const KeyValueStore& value,
                                     Error* /*error*/) {
  if (args_ == value) {
    return false;
  }
  args_ = value;
  return true;
}

void StaticIPParameters::Reset() {
  ClearSavedParameters();
  args_ = KeyValueStore();
}

}  // namespace shill
