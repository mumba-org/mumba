// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/default_profile.h"

#include <base/files/file_path.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>

#include <string>
#include <vector>

#include "shill/adaptor_interfaces.h"
#include "shill/manager.h"
#include "shill/portal_detector.h"
#include "shill/resolver.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"

namespace shill {

namespace {
// ConnectionIdSalt was removed in crrev.com/c/2814180.
// This was left here to remove ConnectionIdSalt entries from profiles.
const char kStorageConnectionIdSaltDeprecated[] = "ConnectionIdSalt";
// LinkMonitorTechnologies was removed in crrev.com/c/2827849.
// This was left here to remove ConnectionIdSalt entries from profiles.
const char kStorageLinkMonitorTechnologiesDeprecated[] =
    "LinkMonitorTechnologies";
}  // namespace

// static
const char DefaultProfile::kDefaultId[] = "default";
// static
const char DefaultProfile::kStorageArpGateway[] = "ArpGateway";
// static
const char DefaultProfile::kStorageCheckPortalList[] = "CheckPortalList";
// static
const char DefaultProfile::kStorageIgnoredDNSSearchPaths[] =
    "IgnoredDNSSearchPaths";
// static
const char DefaultProfile::kStorageName[] = "Name";
// static
const char DefaultProfile::kStorageNoAutoConnectTechnologies[] =
    "NoAutoConnectTechnologies";
// static
const char DefaultProfile::kStorageProhibitedTechnologies[] =
    "ProhibitedTechnologies";
// static
const char DefaultProfile::kStorageUseSwanctlDriver[] = "UseSwanctlDriver";
// b/221171651: This string must stay consistent with the storage id used
// previously by DhcpProperties.
// static
const char DefaultProfile::kStorageDhcpHostname[] = "Hostname";
#if !defined(DISABLE_WIFI)
// static
const char DefaultProfile::kStorageWifiGlobalFTEnabled[] =
    "WiFi.GlobalFTEnabled";
#endif  // DISABLE_WIFI

DefaultProfile::DefaultProfile(Manager* manager,
                               const base::FilePath& storage_directory,
                               const std::string& profile_id,
                               const ManagerProperties& manager_props)
    : Profile(manager, Identifier(profile_id), storage_directory, true),
      profile_id_(profile_id),
      props_(manager_props) {
  PropertyStore* store = this->mutable_store();
  store->RegisterConstBool(kArpGatewayProperty, &manager_props.arp_gateway);
  store->RegisterConstString(kCheckPortalListProperty,
                             &manager_props.check_portal_list);
  store->RegisterConstString(kIgnoredDNSSearchPathsProperty,
                             &manager_props.ignored_dns_search_paths);
  store->RegisterConstString(kNoAutoConnectTechnologiesProperty,
                             &manager_props.no_auto_connect_technologies);
  store->RegisterConstString(kProhibitedTechnologiesProperty,
                             &manager_props.prohibited_technologies);
  HelpRegisterConstDerivedBool(kUseSwanctlDriver,
                               &DefaultProfile::GetUseSwanctlDriver);
#if !defined(DISABLE_WIFI)
  HelpRegisterConstDerivedBool(kWifiGlobalFTEnabledProperty,
                               &DefaultProfile::GetFTEnabled);
#endif  // DISABLE_WIFI
  set_persistent_profile_path(
      GetFinalStoragePath(storage_directory, Identifier(profile_id)));
}

DefaultProfile::~DefaultProfile() = default;

void DefaultProfile::HelpRegisterConstDerivedBool(
    const std::string& name, bool (DefaultProfile::*get)(Error*)) {
  this->mutable_store()->RegisterDerivedBool(
      name, BoolAccessor(new CustomAccessor<DefaultProfile, bool>(
                this, get, nullptr, nullptr)));
}

bool DefaultProfile::GetUseSwanctlDriver(Error* error) {
  return manager()->GetUseSwanctlDriver(error);
}

#if !defined(DISABLE_WIFI)
bool DefaultProfile::GetFTEnabled(Error* error) {
  return manager()->GetFTEnabled(error);
}
#endif  // DISABLE_WIFI

void DefaultProfile::LoadManagerProperties(ManagerProperties* manager_props) {
  storage()->GetBool(kStorageId, kStorageArpGateway,
                     &manager_props->arp_gateway);
  if (!storage()->GetString(kStorageId, kStorageCheckPortalList,
                            &manager_props->check_portal_list)) {
    manager_props->check_portal_list = PortalDetector::kDefaultCheckPortalList;
  }
  if (!storage()->GetString(kStorageId, kStorageIgnoredDNSSearchPaths,
                            &manager_props->ignored_dns_search_paths)) {
    manager_props->ignored_dns_search_paths =
        Resolver::kDefaultIgnoredSearchList;
  }
  if (!storage()->GetString(kStorageId, kStorageNoAutoConnectTechnologies,
                            &manager_props->no_auto_connect_technologies)) {
    manager_props->no_auto_connect_technologies = "";
  }

  // This used to be loaded from the default profile, but now it is fixed.
  manager_props->portal_http_url = PortalDetector::kDefaultHttpUrl;
  manager_props->portal_https_url = PortalDetector::kDefaultHttpsUrl;
  manager_props->portal_fallback_http_urls =
      std::vector<std::string>(PortalDetector::kDefaultFallbackHttpUrls.begin(),
                               PortalDetector::kDefaultFallbackHttpUrls.end());
  manager_props->portal_fallback_https_urls = std::vector<std::string>(
      PortalDetector::kDefaultFallbackHttpsUrls.begin(),
      PortalDetector::kDefaultFallbackHttpsUrls.end());

  if (!storage()->GetString(kStorageId, kStorageProhibitedTechnologies,
                            &manager_props->prohibited_technologies)) {
    manager_props->prohibited_technologies = "";
  }

  if (!storage()->GetString(kStorageId, kStorageDhcpHostname,
                            &manager_props->dhcp_hostname)) {
    manager_props->dhcp_hostname = "";
  }

  bool use_swanctl_driver;
  if (storage()->GetBool(kStorageId, kStorageUseSwanctlDriver,
                         &use_swanctl_driver)) {
    manager_props->use_swanctl_driver = use_swanctl_driver;
  }
#if !defined(DISABLE_WIFI)
  bool ft_enabled;
  if (storage()->GetBool(kStorageId, kStorageWifiGlobalFTEnabled,
                         &ft_enabled)) {
    manager_props->ft_enabled = ft_enabled;
  }
#endif  // DISABLE_WIFI
}

bool DefaultProfile::ConfigureService(const ServiceRefPtr& service) {
  if (Profile::ConfigureService(service)) {
    return true;
  }
  if (service->technology() == Technology::kEthernet) {
    // Ethernet services should have an affinity towards the default profile,
    // so even if a new Ethernet service has no known configuration, accept
    // it anyway.
    UpdateService(service);
    service->SetProfile(this);
    return true;
  }
  return false;
}

bool DefaultProfile::Save() {
  // ConnectionIdSalt was removed in crrev.com/c/2814180.
  storage()->DeleteKey(kStorageId, kStorageConnectionIdSaltDeprecated);
  // LinkMonitorTechnologies was removed in crrev.com/c/2827849.
  storage()->DeleteKey(kStorageId, kStorageLinkMonitorTechnologiesDeprecated);

  storage()->SetBool(kStorageId, kStorageArpGateway, props_.arp_gateway);
  storage()->SetString(kStorageId, kStorageName, GetFriendlyName());
  storage()->SetString(kStorageId, kStorageCheckPortalList,
                       props_.check_portal_list);
  storage()->SetString(kStorageId, kStorageIgnoredDNSSearchPaths,
                       props_.ignored_dns_search_paths);
  storage()->SetString(kStorageId, kStorageNoAutoConnectTechnologies,
                       props_.no_auto_connect_technologies);
  storage()->SetString(kStorageId, kStorageProhibitedTechnologies,
                       props_.prohibited_technologies);
  if (props_.use_swanctl_driver.has_value()) {
    storage()->SetBool(kStorageId, kStorageUseSwanctlDriver,
                       props_.use_swanctl_driver.value());
  }
  if (!props_.dhcp_hostname.empty()) {
    storage()->SetString(kStorageId, kStorageDhcpHostname,
                         props_.dhcp_hostname);
  }
#if !defined(DISABLE_WIFI)
  if (props_.ft_enabled.has_value()) {
    storage()->SetBool(kStorageId, kStorageWifiGlobalFTEnabled,
                       props_.ft_enabled.value());
  }
#endif  // DISABLE_WIFI
  return Profile::Save();
}

bool DefaultProfile::UpdateDevice(const DeviceRefPtr& device) {
  return device->Save(storage()) && storage()->Flush();
}

}  // namespace shill
