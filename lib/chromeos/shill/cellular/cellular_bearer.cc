// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_bearer.h"

#include <ModemManager/ModemManager.h>

#include <base/bind.h>
//#include <base/check.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/control_interface.h"
#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
static std::string ObjectID(const CellularBearer* c) {
  return "(cellular_bearer)";
}
}  // namespace Logging

namespace {

const char kPropertyAddress[] = "address";
const char kPropertyDNS1[] = "dns1";
const char kPropertyDNS2[] = "dns2";
const char kPropertyDNS3[] = "dns3";
const char kPropertyGateway[] = "gateway";
const char kPropertyMethod[] = "method";
const char kPropertyPrefix[] = "prefix";
const char kPropertyMtu[] = "mtu";

IPConfig::Method ConvertMMBearerIPConfigMethod(uint32_t method) {
  switch (method) {
    case MM_BEARER_IP_METHOD_PPP:
      return IPConfig::kMethodPPP;
    case MM_BEARER_IP_METHOD_STATIC:
      return IPConfig::kMethodStatic;
    case MM_BEARER_IP_METHOD_DHCP:
      return IPConfig::kMethodDHCP;
    default:
      return IPConfig::kMethodUnknown;
  }
}

}  // namespace

CellularBearer::CellularBearer(ControlInterface* control_interface,
                               const RpcIdentifier& dbus_path,
                               const std::string& dbus_service)
    : control_interface_(control_interface),
      dbus_path_(dbus_path),
      dbus_service_(dbus_service) {
  CHECK(control_interface_);
}

CellularBearer::~CellularBearer() = default;

bool CellularBearer::Init() {
  SLOG(this, 3) << __func__ << ": path='" << dbus_path_.value()
                << "', service='" << dbus_service_ << "'";

  dbus_properties_proxy_ =
      control_interface_->CreateDBusPropertiesProxy(dbus_path_, dbus_service_);
  // It is possible that ProxyFactory::CreateDBusPropertiesProxy() returns
  // nullptr as the bearer DBus object may no longer exist.
  if (!dbus_properties_proxy_) {
    LOG(WARNING) << "Failed to create DBus properties proxy for bearer '"
                 << dbus_path_.value() << "'. Bearer is likely gone.";
    return false;
  }

  dbus_properties_proxy_->SetPropertiesChangedCallback(
      base::Bind(&CellularBearer::OnPropertiesChanged, base::Unretained(this)));
  UpdateProperties();
  return true;
}

void CellularBearer::GetIPConfigMethodAndProperties(
    const KeyValueStore& properties,
    IPAddress::Family address_family,
    IPConfig::Method* ipconfig_method,
    std::unique_ptr<IPConfig::Properties>* ipconfig_properties) const {
  DCHECK(ipconfig_method);
  DCHECK(ipconfig_properties);

  uint32_t method = MM_BEARER_IP_METHOD_UNKNOWN;
  if (properties.Contains<uint32_t>(kPropertyMethod)) {
    method = properties.Get<uint32_t>(kPropertyMethod);
  } else {
    SLOG(this, 2) << "Bearer '" << dbus_path_.value()
                  << "' does not specify an IP configuration method.";
  }

  *ipconfig_method = ConvertMMBearerIPConfigMethod(method);
  ipconfig_properties->reset();

  if (*ipconfig_method != IPConfig::kMethodStatic)
    return;

  if (!properties.Contains<std::string>(kPropertyAddress) ||
      !properties.Contains<std::string>(kPropertyGateway)) {
    SLOG(this, 2) << "Bearer '" << dbus_path_.value()
                  << "' static IP configuration does not specify valid "
                     "address/gateway information.";
    *ipconfig_method = IPConfig::kMethodUnknown;
    return;
  }

  ipconfig_properties->reset(new IPConfig::Properties);
  (*ipconfig_properties)->address_family = address_family;
  (*ipconfig_properties)->address =
      properties.Get<std::string>(kPropertyAddress);
  (*ipconfig_properties)->gateway =
      properties.Get<std::string>(kPropertyGateway);

  // Set method string for kMethodStatic
  if ((*ipconfig_properties)->address_family == IPAddress::kFamilyIPv4) {
    (*ipconfig_properties)->method = kTypeIPv4;
  } else if ((*ipconfig_properties)->address_family == IPAddress::kFamilyIPv6) {
    (*ipconfig_properties)->method = kTypeIPv6;
  }

  uint32_t prefix;
  if (!properties.Contains<uint32_t>(kPropertyPrefix)) {
    prefix = IPAddress::GetMaxPrefixLength(address_family);
  } else {
    prefix = properties.Get<uint32_t>(kPropertyPrefix);
  }
  (*ipconfig_properties)->subnet_prefix = prefix;

  if (properties.Contains<std::string>(kPropertyDNS1)) {
    (*ipconfig_properties)
        ->dns_servers.push_back(properties.Get<std::string>(kPropertyDNS1));
  }
  if (properties.Contains<std::string>(kPropertyDNS2)) {
    (*ipconfig_properties)
        ->dns_servers.push_back(properties.Get<std::string>(kPropertyDNS2));
  }
  if (properties.Contains<std::string>(kPropertyDNS3)) {
    (*ipconfig_properties)
        ->dns_servers.push_back(properties.Get<std::string>(kPropertyDNS3));
  }
  if (properties.Contains<uint32_t>(kPropertyMtu)) {
    uint32_t mtu = properties.Get<uint32_t>(kPropertyMtu);
    // TODO(b/139816862): A larger-than-expected MTU value has been observed
    // on some modem. Here we temporarily ignore any MTU value larger than
    // |IPConfig::kDefaultMTU| until the issue has been addressed on the modem
    // side. Remove this workaround later.
    if (mtu <= static_cast<uint32_t>(IPConfig::kDefaultMTU)) {
      (*ipconfig_properties)->mtu = mtu;
    }
  }
}

void CellularBearer::ResetProperties() {
  connected_ = false;
  data_interface_.clear();
  ipv4_config_method_ = IPConfig::kMethodUnknown;
  ipv4_config_properties_.reset();
  ipv6_config_method_ = IPConfig::kMethodUnknown;
  ipv6_config_properties_.reset();
}

void CellularBearer::UpdateProperties() {
  ResetProperties();

  if (!dbus_properties_proxy_)
    return;

  auto properties = dbus_properties_proxy_->GetAll(MM_DBUS_INTERFACE_BEARER);
  OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
}

void CellularBearer::OnPropertiesChanged(
    const std::string& interface, const KeyValueStore& changed_properties) {
  SLOG(this, 3) << __func__ << ": path=" << dbus_path_.value()
                << ", interface=" << interface;

  if (interface != MM_DBUS_INTERFACE_BEARER)
    return;

  if (changed_properties.Contains<bool>(MM_BEARER_PROPERTY_CONNECTED)) {
    connected_ = changed_properties.Get<bool>(MM_BEARER_PROPERTY_CONNECTED);
  }

  if (changed_properties.Contains<std::string>(MM_BEARER_PROPERTY_INTERFACE)) {
    data_interface_ =
        changed_properties.Get<std::string>(MM_BEARER_PROPERTY_INTERFACE);
  }

  if (changed_properties.Contains<KeyValueStore>(
          MM_BEARER_PROPERTY_IP4CONFIG)) {
    KeyValueStore ipconfig =
        changed_properties.Get<KeyValueStore>(MM_BEARER_PROPERTY_IP4CONFIG);
    GetIPConfigMethodAndProperties(ipconfig, IPAddress::kFamilyIPv4,
                                   &ipv4_config_method_,
                                   &ipv4_config_properties_);
  }
  if (changed_properties.Contains<KeyValueStore>(
          MM_BEARER_PROPERTY_IP6CONFIG)) {
    KeyValueStore ipconfig =
        changed_properties.Get<KeyValueStore>(MM_BEARER_PROPERTY_IP6CONFIG);
    GetIPConfigMethodAndProperties(ipconfig, IPAddress::kFamilyIPv6,
                                   &ipv6_config_method_,
                                   &ipv6_config_properties_);
  }
}

}  // namespace shill
