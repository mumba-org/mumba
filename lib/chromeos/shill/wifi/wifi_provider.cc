// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_provider.h"

#include <stdlib.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include <base/bind.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/byte_string.h"
#include "shill/net/ieee80211.h"
#include "shill/profile.h"
#include "shill/store/key_value_store.h"
#include "shill/store/store_interface.h"
#include "shill/technology.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
static std::string ObjectID(const WiFiProvider* w) {
  return "(wifi_provider)";
}
}  // namespace Logging

namespace {

// We used to store a few properties under this group entry, but they've been
// deprecated. Remove after M-88.
const char kWiFiProviderStorageId[] = "provider_of_wifi";

// Note that WiFiProvider generates some manager-level errors, because it
// implements the WiFi portion of the Manager.GetService flimflam API. The
// API is implemented here, rather than in manager, to keep WiFi-specific
// logic in the right place.
const char kManagerErrorSSIDRequired[] = "must specify SSID";
const char kManagerErrorSSIDTooLong[] = "SSID is too long";
const char kManagerErrorSSIDTooShort[] = "SSID is too short";
const char kManagerErrorInvalidSecurityClass[] = "invalid security class";
const char kManagerErrorInvalidServiceMode[] = "invalid service mode";

// Retrieve a WiFi service's identifying properties from passed-in |args|.
// Returns true if |args| are valid and populates |ssid|, |mode|,
// |security_class| and |hidden_ssid|, if successful.  Otherwise, this function
// returns false and populates |error| with the reason for failure.  It
// is a fatal error if the "Type" parameter passed in |args| is not kWiFi.
bool GetServiceParametersFromArgs(const KeyValueStore& args,
                                  std::vector<uint8_t>* ssid_bytes,
                                  std::string* mode,
                                  std::string* security_class,
                                  bool* hidden_ssid,
                                  Error* error) {
  CHECK_EQ(args.Lookup<std::string>(kTypeProperty, ""), kTypeWifi);

  std::string mode_test = args.Lookup<std::string>(kModeProperty, kModeManaged);
  if (!WiFiService::IsValidMode(mode_test)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          kManagerErrorInvalidServiceMode);
    return false;
  }

  std::vector<uint8_t> ssid;
  if (args.Contains<std::string>(kWifiHexSsid)) {
    std::string ssid_hex_string = args.Get<std::string>(kWifiHexSsid);
    if (!base::HexStringToBytes(ssid_hex_string, &ssid)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Hex SSID parameter is not valid");
      return false;
    }
  } else if (args.Contains<std::string>(kSSIDProperty)) {
    std::string ssid_string = args.Get<std::string>(kSSIDProperty);
    ssid = std::vector<uint8_t>(ssid_string.begin(), ssid_string.end());
  } else {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          kManagerErrorSSIDRequired);
    return false;
  }

  if (ssid.size() < 1) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidNetworkName,
                          kManagerErrorSSIDTooShort);
    return false;
  }

  if (ssid.size() > IEEE_80211::kMaxSSIDLen) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidNetworkName,
                          kManagerErrorSSIDTooLong);
    return false;
  }

  if (args.Contains<std::string>(kSecurityProperty)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unexpected Security property");
    return false;
  }

  const std::string kDefaultSecurity = kSecurityNone;
  if (args.Contains<std::string>(kSecurityClassProperty)) {
    std::string security_class_test =
        args.Lookup<std::string>(kSecurityClassProperty, kDefaultSecurity);
    if (!WiFiService::IsValidSecurityClass(security_class_test)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            kManagerErrorInvalidSecurityClass);
      return false;
    }
    *security_class = security_class_test;
  } else {
    *security_class = kDefaultSecurity;
  }

  *ssid_bytes = ssid;
  *mode = mode_test;

  // If the caller hasn't specified otherwise, we assume it is a hidden service.
  *hidden_ssid = args.Lookup<bool>(kWifiHiddenSsid, true);

  return true;
}

// Retrieve a WiFi service's identifying properties from passed-in |storage|.
// Return true if storage contain valid parameter values and populates |ssid|,
// |mode|, |security_class| and |hidden_ssid|. Otherwise, this function returns
// false and populates |error| with the reason for failure.
bool GetServiceParametersFromStorage(const StoreInterface* storage,
                                     const std::string& entry_name,
                                     std::vector<uint8_t>* ssid_bytes,
                                     std::string* mode,
                                     std::string* security_class,
                                     bool* hidden_ssid,
                                     Error* error) {
  // Verify service type.
  std::string type;
  if (!storage->GetString(entry_name, WiFiService::kStorageType, &type) ||
      type != kTypeWifi) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unspecified or invalid network type");
    return false;
  }

  std::string ssid_hex;
  if (!storage->GetString(entry_name, WiFiService::kStorageSSID, &ssid_hex) ||
      !base::HexStringToBytes(ssid_hex, ssid_bytes)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unspecified or invalid SSID");
    return false;
  }

  if (!storage->GetString(entry_name, WiFiService::kStorageMode, mode) ||
      mode->empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Network mode not specified");
    return false;
  }

  if (!storage->GetString(entry_name, WiFiService::kStorageSecurityClass,
                          security_class) ||
      !WiFiService::IsValidSecurityClass(*security_class)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unspecified or invalid security class");
    return false;
  }

  if (!storage->GetBool(entry_name, WiFiService::kStorageHiddenSSID,
                        hidden_ssid)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Hidden SSID not specified");
    return false;
  }
  return true;
}

}  // namespace

WiFiProvider::WiFiProvider(Manager* manager)
    : manager_(manager), running_(false), disable_vht_(false) {}

WiFiProvider::~WiFiProvider() = default;

void WiFiProvider::Start() {
  running_ = true;
}

void WiFiProvider::Stop() {
  SLOG(this, 2) << __func__;
  while (!services_.empty()) {
    WiFiServiceRefPtr service = services_.back();
    ForgetService(service);
    SLOG(this, 3) << "WiFiProvider deregistering service "
                  << service->log_name();
    manager_->DeregisterService(service);
  }
  service_by_endpoint_.clear();
  running_ = false;
}

void WiFiProvider::CreateServicesFromProfile(const ProfileRefPtr& profile) {
  const StoreInterface* storage = profile->GetConstStorage();
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  bool created_hidden_service = false;
  for (const auto& group : storage->GetGroupsWithProperties(args)) {
    std::vector<uint8_t> ssid_bytes;
    std::string network_mode;
    std::string security_class;
    bool is_hidden = false;
    if (!GetServiceParametersFromStorage(storage, group, &ssid_bytes,
                                         &network_mode, &security_class,
                                         &is_hidden, nullptr)) {
      continue;
    }

    if (FindService(ssid_bytes, network_mode, security_class)) {
      // If service already exists, we have nothing to do, since the
      // service has already loaded its configuration from storage.
      // This is guaranteed to happen in the single case where
      // CreateServicesFromProfile() is called on a WiFiProvider from
      // Manager::PushProfile():
      continue;
    }

    AddService(ssid_bytes, network_mode, security_class, is_hidden);

    // By registering the service in AddService, the rest of the configuration
    // will be loaded from the profile into the service via ConfigureService().

    if (is_hidden) {
      created_hidden_service = true;
    }
  }

  // If WiFi is unconnected and we created a hidden service as a result
  // of opening the profile, we should initiate a WiFi scan, which will
  // allow us to find any hidden services that we may have created.
  if (created_hidden_service &&
      !manager_->IsTechnologyConnected(Technology::kWiFi)) {
    Error unused_error;
    manager_->RequestScan(kTypeWifi, &unused_error);
  }

  ReportRememberedNetworkCount();

  // Only report service source metrics when a user profile is pushed.
  // This ensures that we have an equal number of samples for the
  // default profile and user profiles.
  if (!profile->IsDefault()) {
    ReportServiceSourceMetrics();
  }
}

ServiceRefPtr WiFiProvider::FindSimilarService(const KeyValueStore& args,
                                               Error* error) const {
  std::vector<uint8_t> ssid;
  std::string mode;
  std::string security_class;
  bool hidden_ssid;

  if (!GetServiceParametersFromArgs(args, &ssid, &mode, &security_class,
                                    &hidden_ssid, error)) {
    return nullptr;
  }

  WiFiServiceRefPtr service(FindService(ssid, mode, security_class));
  if (!service) {
    error->Populate(Error::kNotFound, Error::kServiceNotFoundMsg, FROM_HERE);
  }

  return service;
}

ServiceRefPtr WiFiProvider::CreateTemporaryService(const KeyValueStore& args,
                                                   Error* error) {
  std::vector<uint8_t> ssid;
  std::string mode;
  std::string security_class;
  bool hidden_ssid;

  if (!GetServiceParametersFromArgs(args, &ssid, &mode, &security_class,
                                    &hidden_ssid, error)) {
    return nullptr;
  }

  return new WiFiService(manager_, this, ssid, mode, security_class,
                         hidden_ssid);
}

ServiceRefPtr WiFiProvider::CreateTemporaryServiceFromProfile(
    const ProfileRefPtr& profile, const std::string& entry_name, Error* error) {
  std::vector<uint8_t> ssid;
  std::string mode;
  std::string security_class;
  bool hidden_ssid;
  if (!GetServiceParametersFromStorage(profile->GetConstStorage(), entry_name,
                                       &ssid, &mode, &security_class,
                                       &hidden_ssid, error)) {
    return nullptr;
  }
  return new WiFiService(manager_, this, ssid, mode, security_class,
                         hidden_ssid);
}

ServiceRefPtr WiFiProvider::GetService(const KeyValueStore& args,
                                       Error* error) {
  return GetWiFiService(args, error);
}

WiFiServiceRefPtr WiFiProvider::GetWiFiService(const KeyValueStore& args,
                                               Error* error) {
  std::vector<uint8_t> ssid_bytes;
  std::string mode;
  std::string security_class;
  bool hidden_ssid;

  if (!GetServiceParametersFromArgs(args, &ssid_bytes, &mode, &security_class,
                                    &hidden_ssid, error)) {
    return nullptr;
  }

  WiFiServiceRefPtr service(FindService(ssid_bytes, mode, security_class));
  if (!service) {
    service = AddService(ssid_bytes, mode, security_class, hidden_ssid);
  }

  return service;
}

WiFiServiceRefPtr WiFiProvider::FindServiceForEndpoint(
    const WiFiEndpointConstRefPtr& endpoint) {
  EndpointServiceMap::iterator service_it =
      service_by_endpoint_.find(endpoint.get());
  if (service_it == service_by_endpoint_.end())
    return nullptr;
  return service_it->second;
}

bool WiFiProvider::OnEndpointAdded(const WiFiEndpointConstRefPtr& endpoint) {
  if (!running_) {
    return false;
  }

  WiFiServiceRefPtr service = FindService(
      endpoint->ssid(), endpoint->network_mode(), endpoint->security_mode());
  if (!service) {
    const bool hidden_ssid = false;
    service =
        AddService(endpoint->ssid(), endpoint->network_mode(),
                   WiFiService::ComputeSecurityClass(endpoint->security_mode()),
                   hidden_ssid);
  }

  std::string asgn_endpoint_log = base::StringPrintf(
      "Assigning endpoint %s to service %s", endpoint->bssid_string().c_str(),
      service->log_name().c_str());

  if (!service->HasEndpoints() && service->IsRemembered()) {
    LOG(INFO) << asgn_endpoint_log;
  } else {
    SLOG(this, 1) << asgn_endpoint_log;
  }

  service->AddEndpoint(endpoint);
  service_by_endpoint_[endpoint.get()] = service;

  manager_->UpdateService(service);
  // Return whether the service has already matched with a set of credentials
  // or not.
  return service->parent_credentials() != nullptr;
}

WiFiServiceRefPtr WiFiProvider::OnEndpointRemoved(
    const WiFiEndpointConstRefPtr& endpoint) {
  if (!running_) {
    return nullptr;
  }

  WiFiServiceRefPtr service = FindServiceForEndpoint(endpoint);

  CHECK(service) << "Can't find Service for Endpoint "
                 << "(with BSSID " << endpoint->bssid_string() << ").";

  std::string rmv_endpoint_log = base::StringPrintf(
      "Removed endpoint %s from service %s", endpoint->bssid_string().c_str(),
      service->log_name().c_str());

  service->RemoveEndpoint(endpoint);
  service_by_endpoint_.erase(endpoint.get());

  if (!service->HasEndpoints() && service->IsRemembered()) {
    LOG(INFO) << rmv_endpoint_log;
  } else {
    SLOG(this, 1) << rmv_endpoint_log;
  }

  if (service->HasEndpoints() || service->IsRemembered()) {
    // Keep services around if they are in a profile or have remaining
    // endpoints.
    manager_->UpdateService(service);
    return nullptr;
  }

  ForgetService(service);
  manager_->DeregisterService(service);

  return service;
}

void WiFiProvider::OnEndpointUpdated(const WiFiEndpointConstRefPtr& endpoint) {
  if (!running_) {
    return;
  }

  WiFiService* service = FindServiceForEndpoint(endpoint).get();
  CHECK(service);

  // If the service still matches the endpoint in its new configuration,
  // we need only to update the service.
  if (service->ssid() == endpoint->ssid() &&
      service->mode() == endpoint->network_mode() &&
      service->IsSecurityMatch(endpoint->security_mode())) {
    service->NotifyEndpointUpdated(endpoint);
    return;
  }

  // The endpoint no longer matches the associated service.  Remove the
  // endpoint, so current references to the endpoint are reset, then add
  // it again so it can be associated with a new service.
  OnEndpointRemoved(endpoint);
  OnEndpointAdded(endpoint);
}

bool WiFiProvider::OnServiceUnloaded(
    const WiFiServiceRefPtr& service,
    const PasspointCredentialsRefPtr& credentials) {
  if (credentials) {
    // The service had credentials. We want to remove them and invalidate all
    // the services that were populated with it.
    ForgetCredentials(credentials);
  }

  // If the service still has endpoints, it should remain in the service list.
  if (service->HasEndpoints()) {
    return false;
  }

  // This is the one place where we forget the service but do not also
  // deregister the service with the manager.  However, by returning
  // true below, the manager will do so itself.
  ForgetService(service);
  return true;
}

void WiFiProvider::UpdateStorage(Profile* profile) {
  CHECK(profile);
  StoreInterface* storage = profile->GetStorage();
  // We stored this only to the default profile, but no reason not to delete it
  // from any profile it exists in.
  // Remove after M-88.
  storage->DeleteGroup(kWiFiProviderStorageId);
}

void WiFiProvider::SortServices() {
  std::sort(services_.begin(), services_.end(),
            [](const WiFiServiceRefPtr& a, const WiFiServiceRefPtr& b) -> bool {
              return Service::Compare(a, b, true, {}).first;
            });
}

WiFiServiceRefPtr WiFiProvider::AddService(const std::vector<uint8_t>& ssid,
                                           const std::string& mode,
                                           const std::string& security_class,
                                           bool is_hidden) {
  WiFiServiceRefPtr service =
      new WiFiService(manager_, this, ssid, mode, security_class, is_hidden);

  services_.push_back(service);
  manager_->RegisterService(service);
  return service;
}

WiFiServiceRefPtr WiFiProvider::FindService(const std::vector<uint8_t>& ssid,
                                            const std::string& mode,
                                            const std::string& security) const {
  for (const auto& service : services_) {
    if (service->ssid() == ssid && service->mode() == mode &&
        service->IsSecurityMatch(security)) {
      return service;
    }
  }
  return nullptr;
}

ByteArrays WiFiProvider::GetHiddenSSIDList() {
  SortServices();

  // Create a unique container of hidden SSIDs.
  ByteArrays hidden_ssids;
  for (const auto& service : services_) {
    if (service->hidden_ssid() && service->IsRemembered()) {
      if (base::Contains(hidden_ssids, service->ssid())) {
        LOG(WARNING) << "Duplicate HiddenSSID: " << service->log_name();
        continue;
      }
      hidden_ssids.push_back(service->ssid());
    }
  }
  SLOG(this, 2) << "Found " << hidden_ssids.size() << " hidden services";
  return hidden_ssids;
}

void WiFiProvider::ForgetService(const WiFiServiceRefPtr& service) {
  std::vector<WiFiServiceRefPtr>::iterator it;
  it = std::find(services_.begin(), services_.end(), service);
  if (it == services_.end()) {
    return;
  }
  (*it)->ResetWiFi();
  services_.erase(it);
}

void WiFiProvider::ReportRememberedNetworkCount() {
  metrics()->SendToUMA(
      Metrics::kMetricRememberedWiFiNetworkCount,
      std::count_if(services_.begin(), services_.end(),
                    [](ServiceRefPtr s) { return s->IsRemembered(); }),
      Metrics::kMetricRememberedWiFiNetworkCountMin,
      Metrics::kMetricRememberedWiFiNetworkCountMax,
      Metrics::kMetricRememberedWiFiNetworkCountNumBuckets);
}

void WiFiProvider::ReportServiceSourceMetrics() {
  for (const auto& security_mode :
       {kSecurityNone, kSecurityWep, kSecurityPsk, kSecurity8021x}) {
    metrics()->SendToUMA(
        base::StringPrintf(
            Metrics::
                kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
            security_mode),
        std::count_if(services_.begin(), services_.end(),
                      [security_mode](WiFiServiceRefPtr s) {
                        return s->IsRemembered() &&
                               s->IsSecurityMatch(security_mode) &&
                               s->profile()->IsDefault();
                      }),
        Metrics::kMetricRememberedWiFiNetworkCountMin,
        Metrics::kMetricRememberedWiFiNetworkCountMax,
        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets);
    metrics()->SendToUMA(
        base::StringPrintf(
            Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
            security_mode),
        std::count_if(services_.begin(), services_.end(),
                      [security_mode](WiFiServiceRefPtr s) {
                        return s->IsRemembered() &&
                               s->IsSecurityMatch(security_mode) &&
                               !s->profile()->IsDefault();
                      }),
        Metrics::kMetricRememberedWiFiNetworkCountMin,
        Metrics::kMetricRememberedWiFiNetworkCountMax,
        Metrics::kMetricRememberedWiFiNetworkCountNumBuckets);
  }

  metrics()->SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount,
                       std::count_if(services_.begin(), services_.end(),
                                     [](WiFiServiceRefPtr s) {
                                       return s->IsRemembered() &&
                                              s->hidden_ssid();
                                     }),
                       Metrics::kMetricRememberedWiFiNetworkCountMin,
                       Metrics::kMetricRememberedWiFiNetworkCountMax,
                       Metrics::kMetricRememberedWiFiNetworkCountNumBuckets);

  for (const auto& service : services_) {
    if (service->IsRemembered() && service->hidden_ssid()) {
      metrics()->SendBoolToUMA(Metrics::kMetricHiddenSSIDEverConnected,
                               service->has_ever_connected());
    }
  }
}

void WiFiProvider::ReportAutoConnectableServices() {
  int num_services = NumAutoConnectableServices();
  // Only report stats when there are wifi services available.
  if (num_services) {
    metrics()->NotifyWifiAutoConnectableServices(num_services);
  }
}

int WiFiProvider::NumAutoConnectableServices() {
  const char* reason = nullptr;
  int num_services = 0;
  // Determine the number of services available for auto-connect.
  for (const auto& service : services_) {
    // Service is available for auto connect if it is configured for auto
    // connect, and is auto-connectable.
    if (service->auto_connect() && service->IsAutoConnectable(&reason)) {
      num_services++;
    }
  }
  return num_services;
}

std::vector<ByteString> WiFiProvider::GetSsidsConfiguredForAutoConnect() {
  std::vector<ByteString> results;
  for (const auto& service : services_) {
    if (service->auto_connect()) {
      // Service configured for auto-connect.
      ByteString ssid_bytes(service->ssid());
      results.push_back(ssid_bytes);
    }
  }
  return results;
}

void WiFiProvider::LoadCredentialsFromProfile(const ProfileRefPtr& profile) {
  const StoreInterface* storage = profile->GetConstStorage();
  KeyValueStore args;
  args.Set<std::string>(PasspointCredentials::kStorageType,
                        PasspointCredentials::kTypePasspoint);
  for (const auto& group : storage->GetGroupsWithProperties(args)) {
    PasspointCredentialsRefPtr creds = new PasspointCredentials(group);
    creds->Load(storage);
    creds->SetProfile(profile);
    AddCredentials(creds);
  }
}

void WiFiProvider::UnloadCredentialsFromProfile(const ProfileRefPtr& profile) {
  PasspointCredentialsMap creds(credentials_by_id_);
  for (const auto& [id, c] : creds) {
    if (c != nullptr && c->profile() == profile) {
      // We don't need to call RemoveCredentials with service removal because at
      // Profile removal time, we expect all the services to be removed already.
      RemoveCredentials(c);
    }
  }
}

void WiFiProvider::AddCredentials(
    const PasspointCredentialsRefPtr& credentials) {
  credentials_by_id_[credentials->id()] = credentials;

  DeviceRefPtr device =
      manager_->GetEnabledDeviceWithTechnology(Technology::kWiFi);
  if (!device) {
    return;
  }
  // We can safely do this because GetEnabledDeviceWithTechnology ensures
  // the type of the device is WiFi.
  WiFiRefPtr wifi(static_cast<WiFi*>(device.get()));
  if (!wifi->AddCred(credentials)) {
    SLOG(this, 1) << "Failed to push credentials " << credentials->id()
                  << " to device.";
  }
}

bool WiFiProvider::ForgetCredentials(
    const PasspointCredentialsRefPtr& credentials) {
  if (!credentials ||
      credentials_by_id_.find(credentials->id()) == credentials_by_id_.end()) {
    // Credentials have been removed, nothing to do.
    return true;
  }

  // TODO(b/162106001) handle CA and client cert removal if necessary.

  // Remove the credentials from our credentials set and from the WiFi device.
  bool success = RemoveCredentials(credentials);
  // Find all the services linked to the set.
  std::vector<WiFiServiceRefPtr> to_delete;
  for (auto& service : services_) {
    if (service->parent_credentials() == credentials) {
      // Prevent useless future calls to ForgetCredentials().
      service->set_parent_credentials(nullptr);
      // There's no risk of double removal here because the original service's
      // credentials were reset in WiFiService::Unload().
      to_delete.push_back(service);
    }
  }
  // Delete the services separately to avoid iterating over the list while
  // deleting.
  for (auto& service : to_delete) {
    Error error;
    service->Remove(&error);
  }
  // Delete the credentials set from profile storage.
  StoreInterface* storage = credentials->profile()->GetStorage();
  storage->DeleteGroup(credentials->id());
  return success;
}

bool WiFiProvider::ForgetCredentials(const KeyValueStore& properties) {
  const auto fqdn = properties.Lookup<std::string>(
      kPasspointCredentialsFQDNProperty, std::string());
  const auto package_name = properties.Lookup<std::string>(
      kPasspointCredentialsAndroidPackageNameProperty, std::string());

  bool success = true;
  std::vector<const PasspointCredentialsRefPtr> removed_credentials;
  for (const auto& credentials : credentials_by_id_) {
    if (!fqdn.empty() && credentials.second->GetFQDN() != fqdn) {
      continue;
    }
    if (!package_name.empty() &&
        credentials.second->android_package_name() != package_name) {
      continue;
    }
    removed_credentials.push_back(credentials.second);
  }
  for (const auto& credentials : removed_credentials) {
    success &= ForgetCredentials(credentials);
  }
  return success;
}

bool WiFiProvider::RemoveCredentials(
    const PasspointCredentialsRefPtr& credentials) {
  credentials_by_id_.erase(credentials->id());

  DeviceRefPtr device =
      manager_->GetEnabledDeviceWithTechnology(Technology::kWiFi);
  if (!device) {
    return false;
  }
  // We can safely do this because GetEnabledDeviceWithTechnology ensures
  // the type of the device is WiFi.
  WiFiRefPtr wifi(static_cast<WiFi*>(device.get()));
  if (!wifi->RemoveCred(credentials)) {
    SLOG(this, 1) << "Failed to remove credentials " << credentials->id()
                  << " from the device.";
    return false;
  }
  return true;
}

std::vector<PasspointCredentialsRefPtr> WiFiProvider::GetCredentials() {
  std::vector<PasspointCredentialsRefPtr> list;
  for (const auto& [_, c] : credentials_by_id_) {
    list.push_back(c);
  }
  return list;
}

PasspointCredentialsRefPtr WiFiProvider::FindCredentials(
    const std::string& id) {
  const auto it = credentials_by_id_.find(id);
  if (it == credentials_by_id_.end()) {
    return nullptr;
  }
  return it->second;
}

void WiFiProvider::OnPasspointCredentialsMatches(
    const std::vector<PasspointMatch>& matches) {
  SLOG(this, 1) << __func__;

  // Keep the best match for each service.
  std::map<WiFiService*, PasspointMatch> matches_by_service;
  for (const auto& m : matches) {
    WiFiServiceRefPtr service = FindServiceForEndpoint(m.endpoint);
    if (!service) {
      SLOG(this, 1) << "No service for endpoint " << m.endpoint->bssid_string();
      continue;
    }

    if (service->parent_credentials() &&
        service->match_priority() <= m.priority) {
      // The current match brought better or as good credentials than the
      // new one, we won't override it.
      continue;
    }

    const auto it = matches_by_service.find(service.get());
    if (it == matches_by_service.end()) {
      // No match exists yet, just insert the new one.
      matches_by_service[service.get()] = m;
      continue;
    }

    if (it->second.priority > m.priority) {
      // The new match is better than the previous one
      matches_by_service[service.get()] = m;
    }
  }

  // Populate each service with the credentials contained in the match.
  for (auto& [service_ref, match] : matches_by_service) {
    WiFiServiceRefPtr service(service_ref);
    if (service->connectable() && !service->parent_credentials()) {
      // The service already has non-Passpoint credentials, we don't want to
      // override it.
      continue;
    }

    if (service->parent_credentials() &&
        service->match_priority() < match.priority) {
      // The service is populated with Passpoint credentials and the
      // previous match priority is better than the one we got now.
      // We don't want to override it.
      continue;
    }

    // Ensure the service is updated with the credentials and saved in the same
    // profile as the credentials set.
    service->OnPasspointMatch(match.credentials, match.priority);
    manager_->UpdateService(service);
    if (service->profile() != match.credentials->profile()) {
      manager_->MoveServiceToProfile(service, match.credentials->profile());
    }
  }
}

Metrics* WiFiProvider::metrics() const {
  return manager_->metrics();
}

WiFiProvider::PasspointMatch::PasspointMatch() {}

WiFiProvider::PasspointMatch::PasspointMatch(
    const PasspointCredentialsRefPtr& cred_in,
    const WiFiEndpointRefPtr& endp_in,
    MatchPriority prio_in)
    : credentials(cred_in), endpoint(endp_in), priority(prio_in) {}

}  // namespace shill
