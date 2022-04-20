// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/manager.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <base/bind.h>
#include <base/callback.h>
//#include <base/check.h>
//#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/notreached.h>
#include <base/strings/pattern.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/userdb_utils.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <chromeos/patchpanel/dbus/client.h>

#include "shill/adaptor_interfaces.h"
#include "shill/callbacks.h"
#include "shill/connection.h"
#include "shill/control_interface.h"
#include "shill/dbus/dbus_control.h"
#include "shill/default_profile.h"
#include "shill/device.h"
#include "shill/device_claimer.h"
#include "shill/device_info.h"
#include "shill/ephemeral_profile.h"
#include "shill/error.h"
#include "shill/ethernet/ethernet_provider.h"
#include "shill/ethernet/ethernet_temporary_service.h"
#include "shill/event_dispatcher.h"
#include "shill/geolocation_info.h"
#include "shill/hook_table.h"
#include "shill/http_url.h"
#include "shill/logging.h"
#include "shill/profile.h"
#include "shill/resolver.h"
#include "shill/result_aggregator.h"
#include "shill/service.h"
#include "shill/store/property_accessor.h"
#include "shill/technology.h"
#include "shill/throttler.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/vpn/vpn_service.h"

#if !defined(DISABLE_CELLULAR)
#include "shill/cellular/cellular_service_provider.h"
#include "shill/cellular/modem_info.h"
#endif  // DISABLE_CELLULAR

#if !defined(DISABLE_WIFI)
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi.h"
#include "shill/wifi/wifi_provider.h"
#include "shill/wifi/wifi_service.h"
#endif  // DISABLE_WIFI

#if !defined(DISABLE_WIRED_8021X)
#include "shill/ethernet/ethernet_eap_provider.h"
#include "shill/ethernet/ethernet_eap_service.h"
#endif  // DISABLE_WIRED_8021X

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
#include "shill/supplicant/supplicant_manager.h"
#endif  // !DISABLE_WIFI || !DISABLE_WIRED_8021X

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kManager;
static std::string ObjectID(const Manager* m) {
  return "manager";
}
}  // namespace Logging

namespace {

constexpr char kErrorTypeRequired[] = "must specify service type";

// Time to wait for termination actions to complete, which should be less than
// the upstart job timeout, or otherwise stats for termination actions might be
// lost.
constexpr base::TimeDelta kTerminationActionsTimeout =
    base::Milliseconds(19500);

// Interval for probing various device status, and report them to UMA stats.
constexpr base::TimeDelta kDeviceStatusCheckInterval = base::Minutes(3);

// Interval for attempting to initialize patchpanel connection.
constexpr base::TimeDelta kInitPatchpanelClientInterval = base::Minutes(1);

// Interval for polling patchpanel and refreshing traffic counters.
constexpr base::TimeDelta kTrafficCounterRefreshInterval = base::Minutes(5);

// Technologies to probe for.
const char* const kProbeTechnologies[] = {
    kTypeEthernet,
    kTypeWifi,
    kTypeCellular,
};

// Technologies for which auto-connect is temporarily disabled before a user
// session has started.
//
// shill may manage multiple user profiles and a service may be configured in
// one of the user profiles, or in the default profile, or in a few of them.
// However, the AutoConnect property of the same service is not synchronized
// across multiple profiles, and thus may have a different value depending on
// which profile is used at a given moment. If one user enables auto-connect on
// a service while another user disables auto-connect on the same service, it
// becomes less clear whether auto-connect should be enabled or not before any
// user has logged in. This is particularly problematic for cellular services,
// which may incur data cost. To err on the side of caution, we temporarily
// disable auto-connect for cellular before a user session has started.
const Technology kNoAutoConnectTechnologiesBeforeLoggedIn[] = {
    Technology::kCellular,
};

// Name of the default claimer.
constexpr char kDefaultClaimerName[] = "";

// For VPN drivers that only want to pass traffic for specific users,
// these are the usernames that will be used to create the routing policy
// rules. Also, when an AlwaysOnVpnPackage is set and a corresponding VPN
// service is not active, traffic from these users will blackholed.
// Currently the "user traffic" as defined by these usernames does not include
// e.g. Android apps or system processes like the update engine.
const char* const kUserTrafficUsernames[] = {
    "chronos",         // Traffic originating from chrome and nacl applications
    "debugd",          // crosh terminal
    "cups",            // built-in printing using the cups daemon
    "lpadmin",         // printer configuration utility used by cups
    "kerberosd",       // Chrome OS Kerberos daemon
    "kerberosd-exec",  // Kerberos third party untrusted code
    // While tlsdate is not user traffic, time sync should be attempted over
    // VPN. It is OK to send tlsdate traffic over VPN because it will also try
    // to sync time immediately after boot on the sign-in screen when no VPN can
    // be active.
    // TODO(https://crbug.com/1065378): Find a way for tlsdate to try both with
    // and without VPN explicitly.
    "tlsdate",    // tlsdate daemon (secure time sync)
    "pluginvm",   // plugin vm problem report utility (b/160916677)
    "fuse-smbfs"  // smbfs SMB filesystem daemon
};

// Backoff time increment used to compute the delay before always-on VPN next
// attempt after a connection failure.
constexpr base::TimeDelta kAlwaysOnVpnBackoffDelay = base::Milliseconds(500);
// Maximum shift value used to compute the always-on VPN backoff time.
constexpr uint32_t kAlwaysOnVpnBackoffMaxShift = 7u;

// Copied from patchpanel/net_util.h so avoid circular build dependency with
// libpatchpanel-util.
constexpr uint32_t IPv4Addr(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
  return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

// Known IPv4 address range valid for DNS proxy.
constexpr const struct in_addr kDNSProxyBaseAddr = {
    .s_addr = IPv4Addr(100, 115, 92, 0)};
constexpr const struct in_addr kDNSProxyNetmask = {
    .s_addr = IPv4Addr(255, 255, 254, 0)};

}  // namespace

Manager::Manager(ControlInterface* control_interface,
                 EventDispatcher* dispatcher,
                 Metrics* metrics,
                 const std::string& run_directory,
                 const std::string& storage_directory,
                 const std::string& user_storage_directory)
    : dispatcher_(dispatcher),
      control_interface_(control_interface),
      metrics_(metrics),
      run_path_(run_directory),
      storage_path_(storage_directory),
      user_storage_path_(user_storage_directory),
      user_profile_list_path_(Profile::kUserProfileListPathname),
      adaptor_(control_interface->CreateManagerAdaptor(this)),
      device_info_(this),
#if !defined(DISABLE_CELLULAR)
      modem_info_(new ModemInfo(control_interface, this)),
      cellular_service_provider_(new CellularServiceProvider(this)),
#endif  // DISABLE_CELLULAR
      ethernet_provider_(new EthernetProvider(this)),
#if !defined(DISABLE_WIRED_8021X)
      ethernet_eap_provider_(new EthernetEapProvider(this)),
#endif  // DISABLE_WIRED_8021X
      vpn_provider_(new VPNProvider(this)),
#if !defined(DISABLE_WIFI)
      wifi_provider_(new WiFiProvider(this)),
#endif  // DISABLE_WIFI
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
      supplicant_manager_(new SupplicantManager(this)),
#endif  // !DISABLE_WIFI || !DISABLE_WIRED_8021X
      throttler_(new Throttler(dispatcher, this)),
      resolver_(Resolver::GetInstance()),
      running_(false),
      last_default_physical_service_(nullptr),
      last_default_physical_service_online_(false),
      always_on_vpn_mode_(kAlwaysOnVpnModeOff),
      always_on_vpn_service_(nullptr),
      always_on_vpn_connect_attempts_(0u),
      ephemeral_profile_(new EphemeralProfile(this)),
      use_startup_portal_list_(false),
      device_status_check_task_(
          base::Bind(&Manager::DeviceStatusCheckTask, base::Unretained(this))),
      pending_traffic_counter_request_(false),
      termination_actions_(dispatcher),
      is_wake_on_lan_enabled_(true),
      ignore_unknown_ethernet_(false),
      suppress_autoconnect_(false),
      is_connected_state_(false),
      has_user_session_(false),
      network_throttling_enabled_(false),
      download_rate_kbits_(0),
      upload_rate_kbits_(0),
      should_blackhole_user_traffic_(false) {
  HelpRegisterConstDerivedRpcIdentifier(
      kActiveProfileProperty, &Manager::GetActiveProfileRpcIdentifier);
  HelpRegisterDerivedString(kAlwaysOnVpnPackageProperty,
                            &Manager::GetAlwaysOnVpnPackage,
                            &Manager::SetAlwaysOnVpnPackage);
  store_.RegisterBool(kArpGatewayProperty, &props_.arp_gateway);
  HelpRegisterConstDerivedStrings(kAvailableTechnologiesProperty,
                                  &Manager::AvailableTechnologies);
  HelpRegisterDerivedString(kCheckPortalListProperty,
                            &Manager::GetCheckPortalList,
                            &Manager::SetCheckPortalList);
  HelpRegisterConstDerivedStrings(kConnectedTechnologiesProperty,
                                  &Manager::ConnectedTechnologies);
  store_.RegisterConstString(kConnectionStateProperty, &connection_state_);
  HelpRegisterDerivedString(kDefaultTechnologyProperty,
                            &Manager::DefaultTechnology, nullptr);
  HelpRegisterConstDerivedRpcIdentifier(
      kDefaultServiceProperty, &Manager::GetDefaultServiceRpcIdentifier);
  HelpRegisterConstDerivedRpcIdentifiers(kDevicesProperty,
                                         &Manager::EnumerateDevices);
#if !defined(DISABLE_WIFI)
  HelpRegisterDerivedBool(kDisableWiFiVHTProperty, &Manager::GetDisableWiFiVHT,
                          &Manager::SetDisableWiFiVHT);
  HelpRegisterDerivedBool(kWifiGlobalFTEnabledProperty, &Manager::GetFTEnabled,
                          &Manager::SetFTEnabled);
  store_.RegisterBool(kWifiScanAllowRoamProperty, &props_.scan_allow_roam);
#endif  // DISABLE_WIFI
  HelpRegisterConstDerivedStrings(kEnabledTechnologiesProperty,
                                  &Manager::EnabledTechnologies);
  HelpRegisterDerivedString(kIgnoredDNSSearchPathsProperty,
                            &Manager::GetIgnoredDNSSearchPaths,
                            &Manager::SetIgnoredDNSSearchPaths);
  store_.RegisterString(kNoAutoConnectTechnologiesProperty,
                        &props_.no_auto_connect_technologies);
  store_.RegisterConstString(kPortalHttpUrlProperty, &props_.portal_http_url);
  store_.RegisterConstString(kPortalHttpsUrlProperty, &props_.portal_https_url);
  HelpRegisterDerivedString(kPortalFallbackUrlsStringProperty,
                            &Manager::GetPortalFallbackUrlsString,
                            &Manager::SetPortalFallbackUrlsString);
  HelpRegisterConstDerivedRpcIdentifiers(kProfilesProperty,
                                         &Manager::EnumerateProfiles);
  HelpRegisterDerivedString(kProhibitedTechnologiesProperty,
                            &Manager::GetProhibitedTechnologies,
                            &Manager::SetProhibitedTechnologies);
  HelpRegisterDerivedString(kStateProperty, &Manager::CalculateState, nullptr);
  HelpRegisterConstDerivedRpcIdentifiers(kServicesProperty,
                                         &Manager::EnumerateAvailableServices);
  HelpRegisterConstDerivedRpcIdentifiers(kServiceCompleteListProperty,
                                         &Manager::EnumerateCompleteServices);
  HelpRegisterConstDerivedRpcIdentifiers(kServiceWatchListProperty,
                                         &Manager::EnumerateWatchedServices);
  HelpRegisterConstDerivedStrings(kUninitializedTechnologiesProperty,
                                  &Manager::UninitializedTechnologies);
  store_.RegisterBool(kWakeOnLanEnabledProperty, &is_wake_on_lan_enabled_);
  HelpRegisterConstDerivedStrings(kClaimedDevicesProperty,
                                  &Manager::ClaimedDevices);
  HelpRegisterDerivedKeyValueStore(kDNSProxyDOHProvidersProperty,
                                   &Manager::GetDNSProxyDOHProviders,
                                   &Manager::SetDNSProxyDOHProviders);
  store_.RegisterConstString(kSupportedVPNTypesProperty, &supported_vpn_);
  HelpRegisterDerivedBool(DefaultProfile::kUseSwanctlDriver,
                          &Manager::GetUseSwanctlDriver,
                          &Manager::SetUseSwanctlDriver);
  store_.RegisterString(kDhcpPropertyHostnameProperty, &props_.dhcp_hostname);

  UpdateProviderMapping();

  supported_vpn_ = vpn_provider_->GetSupportedType();

  SLOG(this, 2) << "Manager initialized.";
}

Manager::~Manager() {
  // Clear Device references.
  device_geolocation_info_.clear();

  // Log an error if Service references beyond |services_| still exist.
  for (ServiceRefPtr& service : services_) {
    if (!service->HasOneRef()) {
      LOG(ERROR) << "Service still has multiple references: "
                 << service->GetRpcIdentifier().value();
    }
  }
  services_.clear();

  // Log an error if Device references beyond |devices_| still exist.
  for (DeviceRefPtr& device : devices_) {
    if (!device->HasOneRef()) {
      LOG(ERROR) << "Device still has multiple references: "
                 << device->GetRpcIdentifier().value();
    }
  }
  devices_.clear();
}

void Manager::RegisterAsync(
    const base::Callback<void(bool)>& completion_callback) {
  adaptor_->RegisterAsync(completion_callback);
}

void Manager::OnDhcpPropertyChanged(const std::string& key,
                                    const std::string& value) {
  adaptor_->EmitStringChanged(key, value);
  if (profiles_.size() > 0)
    profiles_.front()->Save();
}

void Manager::SetBlockedDevices(
    const std::vector<std::string>& blocked_devices) {
  blocked_devices_ = blocked_devices;
}

void Manager::SetAllowedDevices(
    const std::vector<std::string>& allowed_devices) {
  allowed_devices_ = allowed_devices;
}

void Manager::Start() {
  LOG(INFO) << "Manager started.";

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  supplicant_manager_->Start();
#endif  // !DISABLE_WIFI || !DISABLE_WIRED_8021X

  power_manager_.reset(new PowerManager(control_interface_));
  power_manager_->Start(
      kTerminationActionsTimeout,
      base::Bind(&Manager::OnSuspendImminent, weak_factory_.GetWeakPtr()),
      base::Bind(&Manager::OnSuspendDone, weak_factory_.GetWeakPtr()),
      base::Bind(&Manager::OnDarkSuspendImminent, weak_factory_.GetWeakPtr()));
  upstart_.reset(new Upstart(control_interface_));

  CHECK(base::CreateDirectory(run_path_)) << run_path_.value();
  const auto filepath = run_path_.Append("resolv.conf");
  CHECK(!filepath.empty());
  resolver_->set_path(filepath);

  if (metrics_) {
    AddDefaultServiceObserver(metrics_);
  }

  InitializeProfiles();
  running_ = true;
  device_info_.Start();
#if !defined(DISABLE_CELLULAR)
  modem_info_->Start();
#endif  // DISABLE_CELLULAR
  for (const auto& provider_mapping : providers_) {
    provider_mapping.second->Start();
  }
  InitializePatchpanelClient();

  // Start task for checking connection status.
  dispatcher_->PostDelayedTask(FROM_HERE, device_status_check_task_.callback(),
                               kDeviceStatusCheckInterval);
}

void Manager::Stop() {
  SLOG(this, 1) << __func__;
  running_ = false;
  // Persist device information to disk;
  for (const auto& device : devices_) {
    UpdateDevice(device);
  }

  // Persist profile, service information to disk.
  for (const auto& profile : profiles_) {
    // Since this happens in a loop, the current manager state is stored to
    // all default profiles in the stack.  This is acceptable because the
    // only time multiple default profiles are loaded are during autotests.
    profile->Save();
  }

  Error e;
  for (const auto& service : services_) {
    if (service->IsActive(nullptr)) {
      service->Disconnect(&e, __func__);
    }
  }

  for (const auto& device : devices_) {
    device->SetEnabled(false);
  }

  for (const auto& provider_mapping : providers_) {
    provider_mapping.second->Stop();
  }
#if !defined(DISABLE_CELLULAR)
  modem_info_.reset();
#endif  // DISABLE_CELLULAR
  device_info_.Stop();
  device_status_check_task_.Cancel();
  sort_services_task_.Cancel();
  init_patchpanel_client_task_.Cancel();
  refresh_traffic_counter_task_.Cancel();
  if (metrics_) {
    RemoveDefaultServiceObserver(metrics_);
  }
  power_manager_->Stop();
  power_manager_.reset();
  patchpanel_client_.reset();
}

void Manager::InitializeProfiles() {
  DCHECK(profiles_.empty());  // The default profile must go first on stack.
  CHECK(base::CreateDirectory(storage_path_)) << storage_path_.value();

  // Ensure that we have storage for the default profile, and that
  // the persistent copy of the default profile is not corrupt.
  scoped_refptr<DefaultProfile> default_profile(new DefaultProfile(
      this, storage_path_, DefaultProfile::kDefaultId, props_));
  // The default profile may fail to initialize if it's corrupted.
  // If so, recreate the default profile.
  if (!default_profile->InitStorage(Profile::kCreateOrOpenExisting, nullptr))
    CHECK(default_profile->InitStorage(Profile::kCreateNew, nullptr));
  // In case we created a new profile, initialize its default values,
  // and then save. This is required for properties such as
  // PortalDetector::kDefaultCheckPortalList to be initialized correctly.
  LoadProperties(default_profile);
  default_profile->Save();
  default_profile = nullptr;  // PushProfileInternal will re-create.

  // Read list of user profiles. This must be done before pushing the
  // default profile, because modifying the profile stack updates the
  // user profile list.
  std::vector<Profile::Identifier> identifiers =
      Profile::LoadUserProfileList(user_profile_list_path_);

  // Push the default profile onto the stack.
  Error error;
  std::string path;
  Profile::Identifier default_profile_id;
  CHECK(Profile::ParseIdentifier(DefaultProfile::kDefaultId,
                                 &default_profile_id));
  PushProfileInternal(default_profile_id, &path, &error);
  CHECK(!profiles_.empty());  // Must have a default profile.

  // Push user profiles onto the stack.
  for (const auto& profile_id : identifiers) {
    PushProfileInternal(profile_id, &path, &error);
  }
}

void Manager::CreateProfile(const std::string& name,
                            std::string* path,
                            Error* error) {
  SLOG(this, 2) << __func__ << " " << name;
  Profile::Identifier ident;
  if (!Profile::ParseIdentifier(name, &ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid profile name " + name);
    return;
  }

  if (HasProfile(ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kAlreadyExists,
                          "Profile name " + name + " is already on stack");
    return;
  }

  ProfileRefPtr profile;
  if (ident.user.empty()) {
    profile = new DefaultProfile(this, storage_path_, ident.identifier, props_);
  } else {
    profile = new Profile(this, ident, user_storage_path_, true);
  }

  if (!profile->InitStorage(Profile::kCreateNew, error)) {
    // |error| will have been populated by InitStorage().
    return;
  }

  // Save profile data out, and then let the scoped pointer fall out of scope.
  if (!profile->Save()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Profile name " + name + " could not be saved");
    return;
  }

  *path = profile->GetRpcIdentifier().value();
}

bool Manager::HasProfile(const Profile::Identifier& ident) {
  for (const auto& profile : profiles_) {
    if (profile->MatchesIdentifier(ident)) {
      return true;
    }
  }
  return false;
}

void Manager::PushProfileInternal(const Profile::Identifier& ident,
                                  std::string* path,
                                  Error* error) {
  if (HasProfile(ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kAlreadyExists,
                          "Profile name " + Profile::IdentifierToString(ident) +
                              " is already on stack");
    return;
  }

  ProfileRefPtr profile;
  if (ident.user.empty()) {
    // Allow a machine-wide-profile to be pushed on the stack only if the
    // profile stack is empty, or if the topmost profile on the stack is
    // also a machine-wide (non-user) profile.
    if (!profiles_.empty() && !profiles_.back()->GetUser().empty()) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Cannot load non-default global profile " +
                                Profile::IdentifierToString(ident) +
                                " on top of a user profile");
      return;
    }

    scoped_refptr<DefaultProfile> default_profile(
        new DefaultProfile(this, storage_path_, ident.identifier, props_));
    if (!default_profile->InitStorage(Profile::kOpenExisting, nullptr)) {
      LOG(ERROR) << "Failed to open default profile.";
      // Try to continue anyway, so that we can be useful in cases
      // where the disk is full.
      default_profile->InitStubStorage();
    }

    LoadProperties(default_profile);
    profile = default_profile;
    LOG(INFO) << "Push default profile.";
  } else {
    profile = new Profile(this, ident, user_storage_path_, true);
    if (!profile->InitStorage(Profile::kOpenExisting, error)) {
      // |error| will have been populated by InitStorage().
      return;
    }
    LOG(INFO) << "Push user profile: " << ident.user;
  }

  profiles_.push_back(profile);

#if !defined(DISABLE_WIFI)
  wifi_provider_->LoadCredentialsFromProfile(profile);
#endif  // !DISABLE_WIFI

  for (ServiceRefPtr& service : services_) {
    service->ClearExplicitlyDisconnected();

    // Offer each registered Service the opportunity to join this new Profile.
    if (profile->ConfigureService(service)) {
      LOG(INFO) << "(Re-)configured service " << service->log_name()
                << " from new profile.";
    }
  }

  // Shop the Profile contents around to Devices which may have configuration
  // stored in these profiles.
  for (DeviceRefPtr& device : devices_) {
    profile->ConfigureDevice(device);
  }

  // Offer the Profile contents to the service providers which will
  // create new services if necessary.
  for (const auto& provider_mapping : providers_) {
    provider_mapping.second->CreateServicesFromProfile(profile);
  }

  // Update the current always-on VPN configuration with the profile.
  UpdateAlwaysOnVpnWith(profile);

  *path = profile->GetRpcIdentifier().value();
  SortServices();
  OnProfilesChanged();
  LOG(INFO) << __func__ << " finished; " << profiles_.size()
            << " profile(s) now present.";
}

void Manager::PushProfile(const std::string& name,
                          std::string* path,
                          Error* error) {
  SLOG(this, 2) << __func__ << " " << name;
  Profile::Identifier ident;
  if (!Profile::ParseIdentifier(name, &ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid profile name " + name);
    return;
  }
  PushProfileInternal(ident, path, error);
}

void Manager::InsertUserProfile(const std::string& name,
                                const std::string& user_hash,
                                std::string* path,
                                Error* error) {
  SLOG(this, 2) << __func__ << " " << name;
  Profile::Identifier ident;
  if (!Profile::ParseIdentifier(name, &ident) || ident.user.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid user profile name " + name);
    return;
  }
  ident.user_hash = user_hash;
  PushProfileInternal(ident, path, error);
}

void Manager::PopProfileInternal() {
  CHECK(!profiles_.empty());
  ProfileRefPtr active_profile = profiles_.back();
  const std::string& user = active_profile->GetUser();
  if (user.empty()) {
    LOG(INFO) << "Pop default profile.";
  } else {
    LOG(INFO) << "Pop user profile: " << user;
  }
  profiles_.pop_back();
  for (auto it = services_.begin(); it != services_.end();) {
    (*it)->ClearExplicitlyDisconnected();
    if (IsServiceEphemeral(*it)) {
      // Not affected, since the EphemeralProfile isn't on the stack.
      // Not logged, since ephemeral services aren't that interesting.
      ++it;
      continue;
    }

    if ((*it)->profile().get() != active_profile.get()) {
      LOG(INFO) << "Skipping unload of service " << (*it)->log_name()
                << ": wasn't using this profile.";
      ++it;
      continue;
    }

    if (MatchProfileWithService(*it)) {
      LOG(INFO) << "Skipping unload of service " << (*it)->log_name()
                << ": re-configured from another profile.";
      ++it;
      continue;
    }

    if (!UnloadService(&it)) {
      LOG(INFO) << "Service " << (*it)->log_name()
                << " not completely unloaded.";
      ++it;
      continue;
    }

    // Service was totally unloaded. No advance of iterator in this
    // case, as UnloadService has updated the iterator for us.
  }

#if !defined(DISABLE_WIFI)
  // Remove Passpoint credentials attached to this profile.
  wifi_provider_->UnloadCredentialsFromProfile(active_profile);
#endif  // !DISABLE_WIFI

  SortServices();
  OnProfilesChanged();
  LOG(INFO) << __func__ << " finished; " << profiles_.size()
            << " profile(s) still present.";
}

void Manager::OnProfilesChanged() {
  Error unused_error;

  adaptor_->EmitRpcIdentifierArrayChanged(kProfilesProperty,
                                          EnumerateProfiles(&unused_error));
  Profile::SaveUserProfileList(user_profile_list_path_, profiles_);
  has_user_session_ = false;
  for (const ProfileRefPtr& profile : profiles_) {
    if (!profile->GetUser().empty()) {
      has_user_session_ = true;
      break;
    }
  }
}

void Manager::PopProfile(const std::string& name, Error* error) {
  SLOG(this, 2) << __func__ << " " << name;
  Profile::Identifier ident;
  if (profiles_.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "Profile stack is empty");
    return;
  }
  ProfileRefPtr active_profile = profiles_.back();
  if (!Profile::ParseIdentifier(name, &ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid profile name " + name);
    return;
  }
  if (!active_profile->MatchesIdentifier(ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kWrongState,
                          name + " is not the active profile");
    return;
  }
  PopProfileInternal();
}

void Manager::PopAnyProfile(Error* error) {
  SLOG(this, 2) << __func__;
  Profile::Identifier ident;
  if (profiles_.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "Profile stack is empty");
    return;
  }
  PopProfileInternal();
}

void Manager::PopAllUserProfiles(Error* /*error*/) {
  SLOG(this, 2) << __func__;
  while (!profiles_.empty() && !profiles_.back()->GetUser().empty()) {
    PopProfileInternal();
  }
}

void Manager::RemoveProfile(const std::string& name, Error* error) {
  Profile::Identifier ident;
  if (!Profile::ParseIdentifier(name, &ident)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid profile name " + name);
    return;
  }

  if (HasProfile(ident)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "Cannot remove profile name " + name + " since it is on stack");
    return;
  }

  ProfileRefPtr profile;
  if (ident.user.empty()) {
    profile = new DefaultProfile(this, storage_path_, ident.identifier, props_);
  } else {
    profile = new Profile(this, ident, user_storage_path_, false);
  }

  // |error| will have been populated if RemoveStorage fails.
  profile->RemoveStorage(error);

  return;
}

void Manager::OnProfileChanged(const ProfileRefPtr& profile) {
  if (IsActiveProfile(profile)) {
    UpdateAlwaysOnVpnWith(profile);
    ResetAlwaysOnVpnBackoff();
    SortServices();
  }
}

bool Manager::DeviceManagementAllowed(const std::string& device_name) {
  if (base::Contains(blocked_devices_, device_name)) {
    return false;
  }
  if (allowed_devices_.empty()) {
    // If no list is specified, all devices are allowed.
    return true;
  }
  if (base::Contains(allowed_devices_, device_name)) {
    return true;
  }
  return false;
}

void Manager::ClaimDevice(const std::string& claimer_name,
                          const std::string& device_name,
                          Error* error) {
  SLOG(this, 2) << __func__;

  // Basic check for device name.
  if (device_name.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Empty device name");
    return;
  }

  if (!DeviceManagementAllowed(device_name)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Not allowed to claim unmanaged device");
    return;
  }

  // Verify default claimer.
  if (claimer_name.empty() &&
      (!device_claimer_ || !device_claimer_->default_claimer())) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "No default claimer");
    return;
  }

  // Create a new device claimer if one doesn't exist yet.
  if (!device_claimer_) {
    // Start a device claimer.  No need to verify the existence of the claimer,
    // since we are using message sender as the claimer name.
    device_claimer_.reset(
        new DeviceClaimer(claimer_name, &device_info_, false));
  }

  // Verify claimer's name, since we only allow one claimer to exist at a time.
  if (device_claimer_->name() != claimer_name) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid claimer name " + claimer_name +
                              ". Claimer " + device_claimer_->name() +
                              " already exist");
    return;
  }

  // Error will be populated by the claimer if failed to claim the device.
  if (!device_claimer_->Claim(device_name, error)) {
    return;
  }

  // Deregister the device from manager if it is registered.
  DeregisterDeviceByLinkName(device_name);
}

void Manager::ReleaseDevice(const std::string& claimer_name,
                            const std::string& device_name,
                            bool* claimer_removed,
                            Error* error) {
  SLOG(this, 2) << __func__;

  *claimer_removed = false;

  if (!DeviceManagementAllowed(device_name)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Not allowed to release unmanaged device");
    return;
  }

  if (!device_claimer_) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Device claimer doesn't exist");
    return;
  }

  // Verify claimer's name, since we only allow one claimer to exist at a time.
  if (device_claimer_->name() != claimer_name) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid claimer name " + claimer_name +
                              ". Claimer " + device_claimer_->name() +
                              " already exist");
    return;
  }

  // Release the device from the claimer. Error should be populated by the
  // claimer if it failed to release the given device.
  device_claimer_->Release(device_name, error);

  // Reset claimer if this is not the default claimer and no more devices are
  // claimed by this claimer.
  if (!device_claimer_->default_claimer() &&
      !device_claimer_->DevicesClaimed()) {
    device_claimer_.reset();
    *claimer_removed = true;
  }
}

void Manager::RemoveService(const ServiceRefPtr& service) {
  LOG(INFO) << __func__ << " for service " << service->log_name();
  if (!IsServiceEphemeral(service)) {
    service->profile()->AbandonService(service);
    if (MatchProfileWithService(service)) {
      // We found another profile to adopt the service; no need to unload.
      UpdateService(service);
      return;
    }
  }
  auto service_it = std::find(services_.begin(), services_.end(), service);
  CHECK(service_it != services_.end());
  if (!UnloadService(&service_it)) {
    UpdateService(service);
  }
  SortServices();
}

bool Manager::HandleProfileEntryDeletion(const ProfileRefPtr& profile,
                                         const std::string& entry_name) {
  bool moved_services = false;
  for (auto it = services_.begin(); it != services_.end();) {
    if ((*it)->profile().get() == profile.get() &&
        (*it)->GetStorageIdentifier() == entry_name) {
      profile->AbandonService(*it);
      if (MatchProfileWithService(*it) || !UnloadService(&it)) {
        ++it;
      }
      moved_services = true;
    } else {
      ++it;
    }
  }
  if (moved_services) {
    SortServices();
  }
  return moved_services;
}

std::map<RpcIdentifier, std::string>
Manager::GetLoadableProfileEntriesForService(
    const ServiceConstRefPtr& service) {
  std::map<RpcIdentifier, std::string> profile_entries;
  for (const auto& profile : profiles_) {
    std::string entry_name =
        service->GetLoadableStorageIdentifier(*profile->GetConstStorage());
    if (!entry_name.empty()) {
      profile_entries[profile->GetRpcIdentifier()] = entry_name;
    }
  }
  return profile_entries;
}

ServiceRefPtr Manager::GetServiceWithStorageIdentifier(
    const std::string& entry_name) {
  for (const auto& service : services_) {
    if (service->GetStorageIdentifier() == entry_name) {
      return service;
    }
  }
  return nullptr;
}

ServiceRefPtr Manager::GetServiceWithStorageIdentifierFromProfile(
    const ProfileRefPtr& profile, const std::string& entry_name, Error* error) {
  for (const auto& service : services_) {
    if (service->profile().get() == profile.get() &&
        service->GetStorageIdentifier() == entry_name) {
      return service;
    }
  }

  SLOG(this, 2) << "Entry " << entry_name
                << " is not registered in the manager";
  return nullptr;
}

ServiceRefPtr Manager::GetServiceWithRpcIdentifier(const RpcIdentifier& id) {
  for (const auto& service : services_) {
    if (service->GetRpcIdentifier() == id) {
      return service;
    }
  }
  return nullptr;
}

ServiceRefPtr Manager::CreateTemporaryServiceFromProfile(
    const ProfileRefPtr& profile, const std::string& entry_name, Error* error) {
  Technology technology = Technology::CreateFromStorageGroup(entry_name);
  if (technology == Technology::kUnknown) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInternalError,
        "Could not determine technology for entry: " + entry_name);
    return nullptr;
  }

  ServiceRefPtr service = nullptr;
  if (base::Contains(providers_, technology)) {
    service = providers_[technology]->CreateTemporaryServiceFromProfile(
        profile, entry_name, error);
  }

  if (!service) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInternalError,
        "Could not create temporary service for technology: " +
            technology.GetName());
    return nullptr;
  }

  profile->LoadService(service);
  return service;
}

ServiceRefPtr Manager::GetServiceWithGUID(const std::string& guid,
                                          Error* error) {
  for (const auto& service : services_) {
    if (service->guid() == guid) {
      return service;
    }
  }

  std::string error_string(base::StringPrintf(
      "Service wth GUID %s is not registered in the manager", guid.c_str()));
  if (error) {
    error->Populate(Error::kNotFound, error_string);
  }
  SLOG(this, 2) << error_string;
  return nullptr;
}

ServiceRefPtr Manager::GetDefaultService() const {
  SLOG(this, 2) << __func__;
  // TODO(b/182777518): Check the connection state instead.
  if (services_.empty() || !FindConnectionFromService(services_[0])) {
    SLOG(this, 2) << "In " << __func__ << ": No default connection exists.";
    return nullptr;
  }
  return services_[0];
}

RpcIdentifier Manager::GetDefaultServiceRpcIdentifier(Error* /*error*/) {
  ServiceRefPtr default_service = GetDefaultService();
  return default_service ? default_service->GetRpcIdentifier()
                         : DBusControl::NullRpcIdentifier();
}

bool Manager::IsTechnologyInList(const std::string& technology_list,
                                 Technology tech) const {
  if (technology_list.empty())
    return false;

  Error error;
  std::vector<Technology> technologies;
  return GetTechnologyVectorFromString(technology_list, &technologies,
                                       &error) &&
         base::Contains(technologies, tech);
}

bool Manager::IsPortalDetectionEnabled(Technology tech) {
  return IsTechnologyInList(GetCheckPortalList(nullptr), tech);
}

void Manager::SetStartupPortalList(const std::string& portal_list) {
  startup_portal_list_ = portal_list;
  use_startup_portal_list_ = true;
}

bool Manager::IsProfileBefore(const ProfileRefPtr& a,
                              const ProfileRefPtr& b) const {
  DCHECK(a != b);
  for (const auto& profile : profiles_) {
    if (profile == a) {
      return true;
    }
    if (profile == b) {
      return false;
    }
  }
  NOTREACHED() << "We should have found both profiles in the profiles_ list!";
  return false;
}

bool Manager::IsServiceEphemeral(const ServiceConstRefPtr& service) const {
  return service->profile() == ephemeral_profile_;
}

bool Manager::IsTechnologyAutoConnectDisabled(Technology technology) const {
  if (!has_user_session_) {
    for (auto disabled_technology : kNoAutoConnectTechnologiesBeforeLoggedIn) {
      if (technology == disabled_technology)
        return true;
    }
  }
  if (technology == Technology::kVPN &&
      always_on_vpn_mode_ != kAlwaysOnVpnModeOff) {
    // Auto connect is disabled on VPNs when the always-on VPN is enabled.
    return true;
  }
  return IsTechnologyInList(props_.no_auto_connect_technologies, technology);
}

bool Manager::IsTechnologyProhibited(Technology technology) const {
  return IsTechnologyInList(props_.prohibited_technologies, technology);
}

void Manager::OnProfileStorageInitialized(Profile* profile) {
#if !defined(DISABLE_WIFI)
  wifi_provider_->UpdateStorage(profile);
#endif  // DISABLE_WIFI
}

DeviceRefPtr Manager::GetEnabledDeviceWithTechnology(
    Technology technology) const {
  for (const auto& device : FilterByTechnology(technology)) {
    if (device->enabled()) {
      return device;
    }
  }
  return nullptr;
}

const ProfileRefPtr& Manager::ActiveProfile() const {
  DCHECK(!profiles_.empty());
  return profiles_.back();
}

bool Manager::IsActiveProfile(const ProfileRefPtr& profile) const {
  return !profiles_.empty() && ActiveProfile().get() == profile.get();
}

bool Manager::MoveServiceToProfile(const ServiceRefPtr& to_move,
                                   const ProfileRefPtr& destination) {
  const ProfileRefPtr from = to_move->profile();
  SLOG(this, 2) << "Moving service " << to_move->log_name() << " to profile "
                << destination->GetFriendlyName() << " from "
                << from->GetFriendlyName();
  return destination->AdoptService(to_move) && from->AbandonService(to_move);
}

ProfileRefPtr Manager::LookupProfileByRpcIdentifier(
    const std::string& profile_rpcid) {
  for (const auto& profile : profiles_) {
    if (profile_rpcid == profile->GetRpcIdentifier().value()) {
      return profile;
    }
  }
  return nullptr;
}

void Manager::SetProfileForService(const ServiceRefPtr& to_set,
                                   const std::string& profile_rpcid,
                                   Error* error) {
  ProfileRefPtr profile = LookupProfileByRpcIdentifier(profile_rpcid);
  if (!profile) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          base::StringPrintf("Unknown Profile %s requested for "
                                             "Service",
                                             profile_rpcid.c_str()));
    return;
  }

  if (!to_set->profile()) {
    // We are being asked to set the profile property of a service that
    // has never been registered.  Now is a good time to register it.
    RegisterService(to_set);
  }

  if (to_set->profile().get() == profile.get()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Service is already connected to this profile");
  } else if (!MoveServiceToProfile(to_set, profile)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Unable to move service to profile");
  }
}

void Manager::SetEnabledStateForTechnology(const std::string& technology_name,
                                           bool enabled_state,
                                           bool persist,
                                           const ResultCallback& callback) {
  Error error;
  Technology id = Technology::CreateFromName(technology_name);
  if (id == Technology::kUnknown) {
    error.Populate(Error::kInvalidArguments, "Unknown technology");
    callback.Run(error);
    return;
  }
  if (enabled_state && IsTechnologyProhibited(id)) {
    error.Populate(Error::kPermissionDenied,
                   "The " + technology_name + " technology is prohibited");
    callback.Run(error);
    return;
  }

  SLOG(this, 2) << __func__ << ": " << technology_name << ": " << enabled_state;

  if (id == Technology::kVPN) {
    // VPN needs special handling since there are no permanent VPN devices.
    // Upon disabling, just disconnect all existing connections here, and new
    // connection requests will be handled in VPNService::OnConnect().
    if (!enabled_state) {
      vpn_provider()->DisconnectAll();
    }
    callback.Run(error);
    return;
  }

  auto result_aggregator(base::MakeRefCounted<ResultAggregator>(callback));
  for (auto& device : devices_) {
    if (device->technology() != id)
      continue;

    error.Populate(Error::kOperationInitiated);
    ResultCallback aggregator_callback(
        base::Bind(&ResultAggregator::ReportResult, result_aggregator));

    if (persist) {
      device->SetEnabledPersistent(enabled_state, &error, aggregator_callback);
    } else {
      device->SetEnabledNonPersistent(enabled_state, &error,
                                      aggregator_callback);
    }

    if (!error.IsOngoing())
      result_aggregator->ReportResult(error);
  }
}

void Manager::UpdateEnabledTechnologies() {
  Error error;
  adaptor_->EmitStringsChanged(kEnabledTechnologiesProperty,
                               EnabledTechnologies(&error));
}

void Manager::UpdateUninitializedTechnologies() {
  Error error;
  adaptor_->EmitStringsChanged(kUninitializedTechnologiesProperty,
                               UninitializedTechnologies(&error));
}

void Manager::SetPassiveMode() {
  CHECK(!device_claimer_);
  // Create a default device claimer to claim devices from  shill as they're
  // detected.  Devices will be managed by remote application, which will use
  // the default claimer to specify the devices for shill to manage.
  device_claimer_.reset(
      new DeviceClaimer(kDefaultClaimerName, &device_info_, true));
}

void Manager::SetIgnoreUnknownEthernet(bool ignore) {
  SLOG(this, 2) << __func__ << "(" << ignore << ")";
  ignore_unknown_ethernet_ = ignore;
}

void Manager::SetAcceptHostnameFrom(const std::string& hostname_from) {
  accept_hostname_from_ = hostname_from;
}

bool Manager::ShouldAcceptHostnameFrom(const std::string& device_name) const {
  return base::MatchPattern(device_name, accept_hostname_from_);
}

bool Manager::IsSuspending() {
  if (power_manager_ && power_manager_->suspending()) {
    return true;
  }
  return false;
}

void Manager::RegisterDevice(const DeviceRefPtr& to_manage) {
  LOG(INFO) << "Device " << to_manage->link_name() << " registered.";
  // Manager is running in passive mode when default claimer is created, which
  // means devices are being managed by remote application. Only manage the
  // device if it was explicitly released by remote application through
  // default claimer.
  if (device_claimer_ && device_claimer_->default_claimer()) {
    if (!device_claimer_->IsDeviceReleased(to_manage->link_name())) {
      Error error;
      device_claimer_->Claim(to_manage->link_name(), &error);
      return;
    }
  }

  for (const auto& device : devices_) {
    if (to_manage == device)
      return;
  }
  devices_.push_back(to_manage);

  LoadDeviceFromProfiles(to_manage);

  if (IsTechnologyProhibited(to_manage->technology())) {
    Error unused_error;
    LOG(INFO) << "Technology prohibited, disabling: "
              << to_manage->technology().GetName();
    to_manage->SetEnabledNonPersistent(false, &unused_error, ResultCallback());
  }

  // If |to_manage| is new, it needs to be persisted.
  UpdateDevice(to_manage);

  if (network_throttling_enabled_ &&
      to_manage->technology().IsPrimaryConnectivityTechnology()) {
    if (devices_.size() == 1) {
      ResultCallback fake;
      throttler_->ThrottleInterfaces(fake, upload_rate_kbits_,
                                     download_rate_kbits_);
    } else {
      // Apply any existing network bandwidth throttling.
      throttler_->ApplyThrottleToNewInterface(to_manage->link_name());
    }
  }

  // In normal usage, running_ will always be true when we are here, however
  // unit tests sometimes do things in otherwise invalid states.
  if (running_ && (to_manage->enabled_persistent() ||
                   to_manage->IsUnderlyingDeviceEnabled())) {
    SLOG(this, 2) << "Enabling registered device type: "
                  << to_manage->technology().GetName();
    to_manage->SetEnabled(true);
  }

  EmitDeviceProperties();
}

void Manager::DeregisterDevice(const DeviceRefPtr& to_forget) {
  LOG(INFO) << __func__ << "(" << to_forget->link_name() << ")";
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if (to_forget.get() == it->get()) {
      SLOG(this, 2) << "Deregistered device: " << to_forget->link_name();
      UpdateDevice(to_forget);
      to_forget->SetEnabled(false);
      device_geolocation_info_.erase(to_forget);
      devices_.erase(it);
      EmitDeviceProperties();
      return;
    }
  }
  SLOG(this, 2) << __func__ << " unknown device: " << to_forget->link_name();
}

void Manager::DeregisterDeviceByLinkName(const std::string& link_name) {
  for (const auto& device : devices_) {
    if (device->link_name() == link_name) {
      DeregisterDevice(device);
      break;
    }
  }
}

std::vector<std::string> Manager::ClaimedDevices(Error* error) {
  std::vector<std::string> results;
  if (!device_claimer_) {
    return results;
  }

  const auto& devices = device_claimer_->claimed_device_names();
  results.resize(devices.size());
  std::copy(devices.begin(), devices.end(), results.begin());
  return results;
}

void Manager::LoadDeviceFromProfiles(const DeviceRefPtr& device) {
  // We are applying device properties from the DefaultProfile, and adding the
  // union of hidden services in all loaded profiles to the device.
  for (const auto& profile : profiles_) {
    // Load device configuration, if any exists, as well as hidden services.
    profile->ConfigureDevice(device);
  }
}

void Manager::EmitDeviceProperties() {
  Error error;
  std::vector<RpcIdentifier> device_paths = EnumerateDevices(&error);
  adaptor_->EmitRpcIdentifierArrayChanged(kDevicesProperty, device_paths);
  adaptor_->EmitStringsChanged(kAvailableTechnologiesProperty,
                               AvailableTechnologies(&error));
  adaptor_->EmitStringsChanged(kEnabledTechnologiesProperty,
                               EnabledTechnologies(&error));
  adaptor_->EmitStringsChanged(kUninitializedTechnologiesProperty,
                               UninitializedTechnologies(&error));
}

void Manager::OnInnerDevicesChanged() {
  EmitDeviceProperties();
}

void Manager::OnDeviceClaimerVanished() {
  // Reset device claimer.
  device_claimer_.reset();
}

RpcIdentifiers Manager::EnumerateDevices(Error* /*error*/) {
  RpcIdentifiers device_rpc_ids;
  for (const auto& device : devices_) {
    device_rpc_ids.push_back(device->GetRpcIdentifier());
  }
  return device_rpc_ids;
}

#if !defined(DISABLE_WIFI)
bool Manager::SetDisableWiFiVHT(const bool& disable_wifi_vht, Error* error) {
  if (disable_wifi_vht == wifi_provider_->disable_vht()) {
    return false;
  }
  wifi_provider_->set_disable_vht(disable_wifi_vht);
  return true;
}

bool Manager::GetDisableWiFiVHT(Error* error) {
  return wifi_provider_->disable_vht();
}

bool Manager::SetFTEnabled(const bool& ft_enabled, Error* error) {
  props_.ft_enabled = ft_enabled;
  return true;
}

bool Manager::GetFTEnabled(Error* error) {
  if (props_.ft_enabled.has_value()) {
    return props_.ft_enabled.value();
  }
  return true;
}
#endif  // DISABLE_WIFI

bool Manager::SetProhibitedTechnologies(
    const std::string& prohibited_technologies, Error* error) {
  std::vector<Technology> technology_vector;
  if (!GetTechnologyVectorFromString(prohibited_technologies,
                                     &technology_vector, error)) {
    return false;
  }
  SLOG(this, 1) << __func__ << ": " << prohibited_technologies;
  for (const auto& technology : technology_vector) {
    ResultCallback result_callback(base::Bind(
        &Manager::OnTechnologyProhibited, base::Unretained(this), technology));
    const bool kPersistentSave = false;
    SetEnabledStateForTechnology(technology.GetName(), false, kPersistentSave,
                                 result_callback);
  }
  props_.prohibited_technologies = prohibited_technologies;

  return true;
}

void Manager::OnTechnologyProhibited(Technology technology,
                                     const Error& error) {
  SLOG(this, 2) << __func__ << " for " << technology;
}

std::string Manager::GetProhibitedTechnologies(Error* error) {
  return props_.prohibited_technologies;
}

bool Manager::HasService(const ServiceRefPtr& service) {
  for (const auto& manager_service : services_) {
    if (manager_service->serial_number() == service->serial_number())
      return true;
  }
  return false;
}

void Manager::RegisterService(const ServiceRefPtr& to_manage) {
  SLOG(this, 2) << "Registering service " << to_manage->log_name();

  MatchProfileWithService(to_manage);

  // Now add to OUR list.
  for (const auto& service : services_) {
    CHECK(to_manage->serial_number() != service->serial_number());
  }
  services_.push_back(to_manage);
  SortServices();
}

void Manager::DeregisterService(const ServiceRefPtr& to_forget) {
  SLOG(this, 2) << "Deregistering service " << to_forget->log_name();
  for (auto it = services_.begin(); it != services_.end(); ++it) {
    if (to_forget->serial_number() == (*it)->serial_number()) {
      (*it)->Unload();
      (*it)->SetProfile(nullptr);
      // We expect the service being deregistered to be destroyed here as well,
      // so need to remove any remaining reference to it.
      if (*it == last_default_physical_service_) {
        last_default_physical_service_ = nullptr;
        last_default_physical_service_online_ = false;
      }
      services_.erase(it);
      SortServices();
      return;
    }
  }
}

bool Manager::UnloadService(
    std::vector<ServiceRefPtr>::iterator* service_iterator) {
  if (!(**service_iterator)->Unload()) {
    return false;
  }

  if (IsServiceAlwaysOnVpn(**service_iterator)) {
    ActiveProfile()->ClearAlwaysOnVpn();
    SetAlwaysOnVpn(kAlwaysOnVpnModeOff, nullptr);
  }

  (**service_iterator)->SetProfile(nullptr);
  *service_iterator = services_.erase(*service_iterator);

  return true;
}

void Manager::UpdateService(const ServiceRefPtr& to_update) {
  CHECK(to_update);
  bool is_interesting_state_change = false;
  const auto& state_it =
      watched_service_states_.find(to_update->serial_number());
  if (state_it != watched_service_states_.end()) {
    is_interesting_state_change = (to_update->state() != state_it->second);
  } else {
    is_interesting_state_change = to_update->IsActive(nullptr);
  }

  std::string failure_message = "";
  if (to_update->failure() != Service::kFailureNone) {
    failure_message = base::StringPrintf(
        " failure: %s", Service::ConnectFailureToString(to_update->failure()));
  }
  // Note: this log is parsed by logprocessor.
  const auto log_message = base::StringPrintf(
      "Service %s updated; state: %s%s", to_update->log_name().c_str(),
      Service::ConnectStateToString(to_update->state()),
      failure_message.c_str());
  if (is_interesting_state_change) {
    LOG(INFO) << log_message;
  } else {
    SLOG(this, 2) << log_message;
  }
  SLOG(this, 2) << "IsConnected(): " << to_update->IsConnected();
  SLOG(this, 2) << "IsConnecting(): " << to_update->IsConnecting();
  if (to_update->IsConnected()) {
    to_update->EnableAndRetainAutoConnect();
    // Ensure that a connected Service is not ephemeral (i.e., we actually
    // persist its settings).
    PersistService(to_update);
  }
  SortServices();
}

void Manager::NotifyServiceStateChanged(const ServiceRefPtr& to_update) {
  UpdateService(to_update);
  if (to_update != last_default_physical_service_) {
    return;
  }
  for (const auto& service : services_) {
    service->OnDefaultServiceStateChanged(to_update);
  }
}

void Manager::UpdateDevice(const DeviceRefPtr& to_update) {
  LOG(INFO) << "Device " << to_update->link_name() << " updated: "
            << (to_update->enabled_persistent() ? "enabled" : "disabled");
  // Saves the device to the topmost profile that accepts it (ordinary
  // profiles don't update but default profiles do). Normally, the topmost
  // updating profile would be the DefaultProfile at the bottom of the stack.
  // Autotests, differ from the normal scenario, however, in that they push a
  // second test-only DefaultProfile.
  for (auto rit = profiles_.rbegin(); rit != profiles_.rend(); ++rit) {
    if ((*rit)->UpdateDevice(to_update)) {
      return;
    }
  }
}

void Manager::PersistService(const ServiceRefPtr& to_update) {
  if (IsServiceEphemeral(to_update)) {
    if (profiles_.empty()) {
      LOG(ERROR) << "Cannot assign profile to service: no profiles exist!";
    } else {
      MoveServiceToProfile(to_update, profiles_.back());
    }
  } else {
    to_update->profile()->UpdateService(to_update);
  }
}

void Manager::LoadProperties(const scoped_refptr<DefaultProfile>& profile) {
  SLOG(this, 2) << __func__;
  profile->LoadManagerProperties(&props_);
  SetIgnoredDNSSearchPaths(props_.ignored_dns_search_paths, nullptr);
}

void Manager::AddTerminationAction(const std::string& name,
                                   const base::Closure& start) {
  termination_actions_.Add(name, start);
}

void Manager::TerminationActionComplete(const std::string& name) {
  SLOG(this, 2) << __func__;
  termination_actions_.ActionComplete(name);
}

void Manager::RemoveTerminationAction(const std::string& name) {
  SLOG(this, 2) << __func__;
  termination_actions_.Remove(name);
}

void Manager::RunTerminationActions(const ResultCallback& done_callback) {
  LOG(INFO) << "Running termination actions.";
  termination_actions_.Run(kTerminationActionsTimeout, done_callback);
}

bool Manager::RunTerminationActionsAndNotifyMetrics(
    const ResultCallback& done_callback) {
  if (termination_actions_.IsEmpty())
    return false;

  RunTerminationActions(done_callback);
  return true;
}

void Manager::AddDefaultServiceObserver(DefaultServiceObserver* observer) {
  default_service_observers_.AddObserver(observer);
}

void Manager::RemoveDefaultServiceObserver(DefaultServiceObserver* observer) {
  default_service_observers_.RemoveObserver(observer);
}

void Manager::UpdateDefaultServices(const ServiceRefPtr& logical_service,
                                    const ServiceRefPtr& physical_service) {
  // Since GetDefaultService returns nullptr when the Service doesn't
  // have a corresponding Connection, this takes into account both a
  // change in default Service and a change in loss/gain of Connection
  // for an unchanged default Service.
  bool logical_service_changed = EmitDefaultService();

  bool physical_service_online =
      physical_service && physical_service->IsOnline();
  bool physical_service_changed =
      (physical_service != last_default_physical_service_ ||
       physical_service_online != last_default_physical_service_online_);

  if (physical_service_changed) {
    // The dns-proxy must be not be used unless the default service is online.
    if (!physical_service_online) {
      UseDNSProxy({});
    } else if (!props_.dns_proxy_addresses.empty()) {
      UseDNSProxy(props_.dns_proxy_addresses);
    }

    last_default_physical_service_ = physical_service;
    last_default_physical_service_online_ = physical_service_online;

    if (physical_service) {
      LOG(INFO) << "Default physical service: " << physical_service->log_name()
                << " (" << (physical_service_online ? "" : "not ") << "online)";
    } else {
      LOG(INFO) << "Default physical service: NONE";
    }
  }

  if (!physical_service_changed && !logical_service_changed) {
    return;
  }

  for (auto& observer : default_service_observers_) {
    if (logical_service_changed) {
      observer.OnDefaultLogicalServiceChanged(logical_service);
    }
    if (physical_service_changed) {
      observer.OnDefaultPhysicalServiceChanged(physical_service);
    }
  }
}

bool Manager::EmitDefaultService() {
  RpcIdentifier rpc_identifier = GetDefaultServiceRpcIdentifier(nullptr);
  if (rpc_identifier == default_service_rpc_identifier_) {
    return false;
  }

  adaptor_->EmitRpcIdentifierChanged(kDefaultServiceProperty, rpc_identifier);
  default_service_rpc_identifier_ = rpc_identifier;
  return true;
}

void Manager::OnSuspendImminent() {
  metrics_->NotifySuspendActionsStarted();
  if (devices_.empty()) {
    // If there are no devices, then suspend actions succeeded synchronously.
    // Make a call to the Manager::OnSuspendActionsComplete directly, since
    // result_aggregator will not.
    OnSuspendActionsComplete(Error(Error::kSuccess));
    return;
  }
  auto result_aggregator(base::MakeRefCounted<ResultAggregator>(
      base::Bind(&Manager::OnSuspendActionsComplete,
                 weak_factory_.GetWeakPtr()),
      dispatcher_, kTerminationActionsTimeout));
  for (const auto& service : services_) {
    ResultCallback aggregator_callback(
        base::Bind(&ResultAggregator::ReportResult, result_aggregator));
    service->OnBeforeSuspend(aggregator_callback);
  }
  for (const auto& device : devices_) {
    ResultCallback aggregator_callback(
        base::Bind(&ResultAggregator::ReportResult, result_aggregator));
    device->OnBeforeSuspend(aggregator_callback);
  }
}

void Manager::OnSuspendDone() {
  metrics_->NotifySuspendDone();
  // Un-suppress auto-connect in case this flag was left set in dark resume.
  set_suppress_autoconnect(false);
  for (const auto& service : services_) {
    service->OnAfterResume();
  }
  SortServices();
  for (const auto& device : devices_) {
    device->OnAfterResume();
  }
}

void Manager::OnDarkSuspendImminent() {
  if (devices_.empty()) {
    // If there are no devices, then suspend actions succeeded synchronously.
    // Make a call to the Manager::OnDarkResumeActionsComplete directly, since
    // result_aggregator will not.
    OnDarkResumeActionsComplete(Error(Error::kSuccess));
    return;
  }
  auto result_aggregator(base::MakeRefCounted<ResultAggregator>(
      base::Bind(&Manager::OnDarkResumeActionsComplete,
                 weak_factory_.GetWeakPtr()),
      dispatcher_, kTerminationActionsTimeout));
  for (const auto& device : devices_) {
    ResultCallback aggregator_callback(
        base::Bind(&ResultAggregator::ReportResult, result_aggregator));
    device->OnDarkResume(aggregator_callback);
  }
}

void Manager::OnSuspendActionsComplete(const Error& error) {
  LOG(INFO) << "Finished suspend actions. Result: " << error;
  metrics_->NotifySuspendActionsCompleted(error.IsSuccess());
  power_manager_->ReportSuspendReadiness();
}

void Manager::OnDarkResumeActionsComplete(const Error& error) {
  LOG(INFO) << "Finished dark resume actions. Result: " << error;
  power_manager_->ReportDarkSuspendReadiness();
}

std::vector<DeviceRefPtr> Manager::FilterByTechnology(Technology tech) const {
  std::vector<DeviceRefPtr> found;
  for (const auto& device : devices_) {
    if (device->technology() == tech)
      found.push_back(device);
  }
  return found;
}

void Manager::HelpRegisterConstDerivedRpcIdentifier(
    const std::string& name, RpcIdentifier (Manager::*get)(Error* error)) {
  store_.RegisterDerivedRpcIdentifier(
      name, RpcIdentifierAccessor(new CustomAccessor<Manager, RpcIdentifier>(
                this, get, nullptr)));
}

void Manager::HelpRegisterConstDerivedRpcIdentifiers(
    const std::string& name, RpcIdentifiers (Manager::*get)(Error* error)) {
  store_.RegisterDerivedRpcIdentifiers(
      name, RpcIdentifiersAccessor(new CustomAccessor<Manager, RpcIdentifiers>(
                this, get, nullptr)));
}

void Manager::HelpRegisterDerivedString(
    const std::string& name,
    std::string (Manager::*get)(Error* error),
    bool (Manager::*set)(const std::string&, Error*)) {
  store_.RegisterDerivedString(
      name,
      StringAccessor(new CustomAccessor<Manager, std::string>(this, get, set)));
}

void Manager::HelpRegisterConstDerivedStrings(const std::string& name,
                                              Strings (Manager::*get)(Error*)) {
  store_.RegisterDerivedStrings(
      name, StringsAccessor(
                new CustomAccessor<Manager, Strings>(this, get, nullptr)));
}

void Manager::HelpRegisterDerivedKeyValueStore(
    const std::string& name,
    KeyValueStore (Manager::*get)(Error* error),
    bool (Manager::*set)(const KeyValueStore& store, Error* error)) {
  store_.RegisterDerivedKeyValueStore(
      name, KeyValueStoreAccessor(
                new CustomAccessor<Manager, KeyValueStore>(this, get, set)));
}

void Manager::HelpRegisterDerivedBool(const std::string& name,
                                      bool (Manager::*get)(Error* error),
                                      bool (Manager::*set)(const bool&,
                                                           Error* error)) {
  store_.RegisterDerivedBool(
      name,
      BoolAccessor(new CustomAccessor<Manager, bool>(this, get, set, nullptr)));
}

void Manager::SortServices() {
  // We might be called in the middle of a series of events that
  // may result in multiple calls to Manager::SortServices, or within
  // an outer loop that may also be traversing the services_ list.
  // Defer this work to the event loop.
  if (sort_services_task_.IsCancelled()) {
    sort_services_task_.Reset(
        base::Bind(&Manager::SortServicesTask, weak_factory_.GetWeakPtr()));
    dispatcher_->PostTask(FROM_HERE, sort_services_task_.callback());
  }
}

void Manager::SortServicesTask() {
  SLOG(this, 4) << "In " << __func__;
  sort_services_task_.Cancel();

  // Refresh all traffic counters before the sort.
  RefreshAllTrafficCountersTask();

  sort(services_.begin(), services_.end(),
       [&order = technology_order_](ServiceRefPtr a, ServiceRefPtr b) {
         return Service::Compare(a, b, true /* compare connectivity */, order)
             .first;
       });

  uint32_t priority = Connection::kDefaultPriority;
  bool found_dns = false;
  ServiceRefPtr old_logical;
  Connection* old_logical_connection;
  int old_logical_priority;
  ServiceRefPtr new_logical;
  Connection* new_logical_connection;
  ServiceRefPtr new_physical;
  for (const auto& service : services_) {
    Connection* conn = FindConnectionFromService(service);
    if (!new_physical && service->technology() != Technology::kVPN) {
      new_physical = service;
    }
    if (conn) {
      if (!found_dns && !conn->dns_servers().empty()) {
        found_dns = true;
        conn->SetUseDNS(true);
      } else {
        conn->SetUseDNS(false);
      }

      if (!new_logical) {
        new_logical = service;
        new_logical_connection = conn;
      }

      priority += Connection::kPriorityStep;
      if (conn->IsDefault()) {
        old_logical = service;
        old_logical_connection = conn;
        old_logical_priority = priority;
      } else {
        conn->SetPriority(priority, new_physical == service);
      }
    }
  }

  if (old_logical && old_logical != new_logical) {
    old_logical_connection->SetPriority(old_logical_priority,
                                        old_logical == new_physical);
  }
  if (new_logical) {
    bool is_primary_physical = new_logical == new_physical;
    new_logical_connection->SetPriority(Connection::kDefaultPriority,
                                        is_primary_physical);
    auto device = FindDeviceFromService(new_logical);
    if (device && device->technology().IsPrimaryConnectivityTechnology() &&
        new_logical->IsPortalled()) {
      SLOG(this, 2)
          << "Restarting portal detection for the new primary device.";
      device->RestartPortalDetection();
    }
  }

  // The physical network changed, the VPN client might be able to connect
  // next time.
  if (last_default_physical_service_ != new_physical) {
    ResetAlwaysOnVpnBackoff();
  }

  Error error;
  adaptor_->EmitRpcIdentifierArrayChanged(kServiceCompleteListProperty,
                                          EnumerateCompleteServices(nullptr));
  adaptor_->EmitRpcIdentifierArrayChanged(kServicesProperty,
                                          EnumerateAvailableServices(nullptr));
  adaptor_->EmitRpcIdentifierArrayChanged(kServiceWatchListProperty,
                                          EnumerateWatchedServices(nullptr));
  adaptor_->EmitStringsChanged(kConnectedTechnologiesProperty,
                               ConnectedTechnologies(&error));
  adaptor_->EmitStringChanged(kDefaultTechnologyProperty,
                              DefaultTechnology(&error));
  UpdateBlackholeUserTraffic();
  UpdateDefaultServices(new_logical, new_physical);
  RefreshConnectionState();
  DetectMultiHomedDevices();
  if (ethernet_provider_)
    ethernet_provider_->RefreshGenericEthernetService();

  AutoConnect();
  ApplyAlwaysOnVpn(new_physical);
}

void Manager::ApplyAlwaysOnVpn(const ServiceRefPtr& physical_service) {
  if (!running_) {
    return;
  }

  SLOG(this, 2) << __func__ << " mode=" << always_on_vpn_mode_ << " service="
                << (always_on_vpn_service_
                        ? always_on_vpn_service_->GetRpcIdentifier().value()
                        : "");

  if (always_on_vpn_mode_ == kAlwaysOnVpnModeOff || !always_on_vpn_service_) {
    // No VPN service to automatically wake-up.
    return;
  }

  if (!physical_service->IsOnline()) {
    // No physical network, we can't connect a VPN.
    ResetAlwaysOnVpnBackoff();
    return;
  }

  if (!always_on_vpn_service_->SupportsAlwaysOnVpn()) {
    // Exclude from always-on VPN all non compatible service like ARC VPNs.
    return;
  }

  if (always_on_vpn_service_->IsConnecting()) {
    // Let the service finish.
    return;
  }

  if (always_on_vpn_service_->IsOnline()) {
    // The VPN is connected, nothing to do.
    ResetAlwaysOnVpnBackoff();
    return;
  }

  if (always_on_vpn_service_->IsFailed()) {
    if (!always_on_vpn_connect_task_.IsCancelled()) {
      // The service has failed to connect but a retry is pending, we have
      // nothing to do until the task is executed.
      return;
    }
  }

  if (always_on_vpn_connect_attempts_ == 0u) {
    // First connection attempt: we can connect directly, no need to schedule
    // a task.
    ConnectAlwaysOnVpn();
    return;
  }

  // We already tried to connect without success, schedule a delayed
  // connection to avoid a connect/failure loop.
  uint32_t shifter =
      std::min(always_on_vpn_connect_attempts_, kAlwaysOnVpnBackoffMaxShift);
  base::TimeDelta delay = (1 << shifter) * kAlwaysOnVpnBackoffDelay;
  always_on_vpn_connect_task_.Reset(
      base::Bind(&Manager::ConnectAlwaysOnVpn, base::Unretained(this)));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               always_on_vpn_connect_task_.callback(), delay);

  LOG(INFO) << "Delayed " << always_on_vpn_service_->friendly_name()
            << " connection in " << delay << " (attempt #"
            << always_on_vpn_connect_attempts_ << ")";
}

void Manager::UpdateAlwaysOnVpnWith(const ProfileRefPtr& profile) {
  std::string mode;
  RpcIdentifier service_id;
  if (profile->GetAlwaysOnVpnSettings(&mode, &service_id)) {
    ServiceRefPtr service = GetServiceWithRpcIdentifier(service_id);
    if (service == nullptr || service->technology() != Technology::kVPN) {
      if (service_id != DBusControl::NullRpcIdentifier()) {
        LOG(WARNING) << "Invalid VPN service: " << service_id.value()
                     << ". Always-on is disabled";
      }
      // The service should be set to null as always-on VPN is disabled.
      SetAlwaysOnVpn(kAlwaysOnVpnModeOff, nullptr);
      return;
    }
    SetAlwaysOnVpn(mode, static_cast<VPNService*>(service.get()));
  }
}

void Manager::SetAlwaysOnVpn(const std::string& mode,
                             VPNServiceRefPtr service) {
  LOG(INFO) << "Setting always-on-vpn to mode=" << mode
            << " service=" << (service ? service->log_name() : "nullptr");

  const std::string previous_mode = always_on_vpn_mode_;
  always_on_vpn_mode_ = mode;
  always_on_vpn_service_ = service;

  // Update VpnLockdown mode below if necessary.
  if (!patchpanel_client_ || previous_mode == mode)
    return;

  if (mode == kAlwaysOnVpnModeStrict) {
    LOG(INFO) << "Starting VPN lockdown";
    patchpanel_client_->SetVpnLockdown(true);
  }

  if (previous_mode == kAlwaysOnVpnModeStrict) {
    LOG(INFO) << "Stopping VPN lockdown";
    patchpanel_client_->SetVpnLockdown(false);
  }
}

void Manager::ConnectAlwaysOnVpn() {
  SLOG(this, 4) << "In " << __func__;

  Error error;
  always_on_vpn_service_->Connect(&error, "Always-on VPN");
  always_on_vpn_connect_attempts_++;
  always_on_vpn_connect_task_.Cancel();
}

void Manager::ResetAlwaysOnVpnBackoff() {
  SLOG(this, 4) << "In " << __func__;

  always_on_vpn_connect_attempts_ = 0u;
  always_on_vpn_connect_task_.Cancel();
}

bool Manager::IsServiceAlwaysOnVpn(const ServiceConstRefPtr& service) const {
  return always_on_vpn_service_ && service->technology() == Technology::kVPN &&
         always_on_vpn_service_->GetStorageIdentifier() ==
             service->GetStorageIdentifier();
}

void Manager::DeviceStatusCheckTask() {
  SLOG(this, 4) << "In " << __func__;

  ConnectionStatusCheck();
  DevicePresenceStatusCheck();

  dispatcher_->PostDelayedTask(FROM_HERE, device_status_check_task_.callback(),
                               kDeviceStatusCheckInterval);
}

void Manager::ConnectionStatusCheck() {
  SLOG(this, 4) << "In " << __func__;
  // Report current connection status.
  Metrics::ConnectionStatus status = Metrics::kConnectionStatusOffline;
  if (IsConnected()) {
    status = Metrics::kConnectionStatusConnected;
    // Check if device is online as well.
    if (IsOnline()) {
      metrics_->NotifyDeviceConnectionStatus(Metrics::kConnectionStatusOnline);
    }
  }
  metrics_->NotifyDeviceConnectionStatus(status);
}

void Manager::DevicePresenceStatusCheck() {
  Error error;
  std::vector<std::string> available_technologies =
      AvailableTechnologies(&error);

  for (const auto& technology : kProbeTechnologies) {
    bool presence = base::Contains(available_technologies, technology);
    metrics_->NotifyDevicePresenceStatus(Technology::CreateFromName(technology),
                                         presence);
  }
}

bool Manager::MatchProfileWithService(const ServiceRefPtr& service) {
  for (auto it = profiles_.rbegin(); it != profiles_.rend(); ++it) {
    if ((*it)->ConfigureService(service)) {
      return true;
    }
  }
  ephemeral_profile_->AdoptService(service);
  return false;
}

void Manager::AutoConnect() {
  if (suppress_autoconnect_) {
    LOG(INFO) << "Auto-connect suppressed -- explicitly suppressed.";
    return;
  }
  if (!running_) {
    LOG(INFO) << "Auto-connect suppressed -- not running.";
    return;
  }
  if (power_manager_ && power_manager_->suspending() &&
      !power_manager_->in_dark_resume()) {
    LOG(INFO) << "Auto-connect suppressed -- system is suspending.";
    return;
  }
  if (services_.empty()) {
    LOG(INFO) << "Auto-connect suppressed -- no services.";
    return;
  }

  if (SLOG_IS_ON(Manager, 4)) {
    SLOG(this, 4) << "Sorted service list for AutoConnect: ";
    for (size_t i = 0; i < services_.size(); ++i) {
      ServiceRefPtr service = services_[i];
      const char* compare_reason = nullptr;
      if (i + 1 < services_.size()) {
        const bool kCompareConnectivityState = true;
        compare_reason =
            Service::Compare(service, services_[i + 1],
                             kCompareConnectivityState, technology_order_)
                .second;
      } else {
        compare_reason = "last";
      }
      SLOG(this, 4) << "Service " << service->log_name()
                    << " Profile: " << service->profile()->GetFriendlyName()
                    << " IsConnected: " << service->IsConnected()
                    << " IsConnecting: " << service->IsConnecting()
                    << " HasEverConnected: " << service->has_ever_connected()
                    << " IsFailed: " << service->IsFailed()
                    << " connectable: " << service->connectable()
                    << " auto_connect: " << service->auto_connect()
                    << " retain_auto_connect: "
                    << service->retain_auto_connect()
                    << " priority: " << service->priority()
                    << " crypto_algorithm: " << service->crypto_algorithm()
                    << " key_rotation: " << service->key_rotation()
                    << " endpoint_auth: " << service->endpoint_auth()
                    << " strength: " << service->strength()
                    << " sorted: " << compare_reason;
    }
  }

#if !defined(DISABLE_WIFI)
  // Report the number of auto-connectable wifi services available when wifi is
  // idle (no active or pending connection), which will trigger auto connect
  // for wifi services.
  if (IsWifiIdle()) {
    wifi_provider_->ReportAutoConnectableServices();
  }
#endif  // DISABLE_WIFI

  // Perform auto-connect.
  for (const auto& service : services_) {
    if (service->auto_connect()) {
      service->AutoConnect();
    }
  }
}

void Manager::ScanAndConnectToBestServices(Error* error) {
#if !defined(DISABLE_WIFI)
  DeviceRefPtr device = GetEnabledDeviceWithTechnology(Technology::kWiFi);
  if (device) {
    static_cast<WiFi*>(device.get())->EnsureScanAndConnectToBestService(error);
    return;
  }
#endif  // DISABLE_WIFI
  ConnectToBestServices(error);
}

void Manager::ConnectToBestServices(Error* /*error*/) {
  dispatcher_->PostTask(FROM_HERE,
                        base::BindOnce(&Manager::ConnectToBestServicesTask,
                                       weak_factory_.GetWeakPtr()));
}

void Manager::ConnectToBestServicesTask() {
  std::vector<ServiceRefPtr> services_copy = services_;
  constexpr bool kCompareConnectivityState = false;
  sort(services_copy.begin(), services_copy.end(),
       [&order = technology_order_](ServiceRefPtr a, ServiceRefPtr b) {
         return Service::Compare(a, b, kCompareConnectivityState, order).first;
       });
  std::set<Technology> connecting_technologies;
  for (const auto& service : services_copy) {
    if (!service->connectable()) {
      // Due to service sort order, it is guaranteed that no services beyond
      // this one will be connectable either.
      break;
    }
    if (!service->auto_connect() || !service->IsVisible()) {
      continue;
    }
    Technology technology = service->technology();
    if (!technology.IsPrimaryConnectivityTechnology() && !IsConnected()) {
      // Non-primary services need some other service connected first.
      continue;
    }
    if (base::Contains(connecting_technologies, technology)) {
      // We have already started a connection for this technology.
      continue;
    }
    if (service->explicitly_disconnected())
      continue;
    connecting_technologies.insert(technology);
    if (!service->IsConnected() && !service->IsConnecting()) {
      // At first blush, it may seem that using Service::AutoConnect might
      // be the right choice, however Service::IsAutoConnectable and its
      // overridden implementations consider a host of conditions which
      // prevent it from attempting a connection which we'd like to ignore
      // for the purposes of this user-initiated action.
      Error error;
      service->Connect(&error, __func__);
      if (error.IsFailure()) {
        LOG(ERROR) << "Connection failed: " << error.message();
      }
    }
  }

  if (SLOG_IS_ON(Manager, 4)) {
    SLOG(this, 4) << "Sorted service list for ConnectToBestServicesTask: ";
    for (size_t i = 0; i < services_copy.size(); ++i) {
      ServiceRefPtr service = services_copy[i];
      const char* compare_reason = nullptr;
      if (i + 1 < services_copy.size()) {
        if (!service->connectable()) {
          // Due to service sort order, it is guaranteed that no services beyond
          // this one are connectable either.
          break;
        }
        compare_reason =
            Service::Compare(service, services_copy[i + 1],
                             kCompareConnectivityState, technology_order_)
                .second;
      } else {
        compare_reason = "last";
      }
      SLOG(this, 4) << "Service " << service->log_name()
                    << " Profile: " << service->profile()->GetFriendlyName()
                    << " IsConnected: " << service->IsConnected()
                    << " IsConnecting: " << service->IsConnecting()
                    << " HasEverConnected: " << service->has_ever_connected()
                    << " IsFailed: " << service->IsFailed()
                    << " connectable: " << service->connectable()
                    << " auto_connect: " << service->auto_connect()
                    << " retain_auto_connect: "
                    << service->retain_auto_connect()
                    << " priority: " << service->priority()
                    << " crypto_algorithm: " << service->crypto_algorithm()
                    << " key_rotation: " << service->key_rotation()
                    << " endpoint_auth: " << service->endpoint_auth()
                    << " strength: " << service->strength()
                    << " sorted: " << compare_reason;
    }
  }
}

void Manager::CreateConnectivityReport(Error* /*error*/) {
  LOG(INFO) << "Creating Connectivity Report";

  // For each of the connected services, perform a single portal detection
  // test to assess connectivity.  The results should be written to the log.
  for (const auto& service : services_) {
    if (!service->IsConnected()) {
      // Service sort order guarantees that no service beyond this one will be
      // connected either.
      break;
    }
    // Get the underlying device for this service and perform connectivity test.
    for (const auto& device : devices_) {
      if (device->IsConnectedToService(service)) {
        if (device->StartConnectivityTest()) {
          SLOG(this, 3) << "Started connectivity test for service "
                        << service->log_name();
        } else {
          SLOG(this, 3) << "Failed to start connectivity test for service "
                        << service->log_name()
                        << " device not reporting IsConnected.";
        }
        break;
      }
    }
  }
}

bool Manager::IsConnected() const {
  // |services_| is sorted such that connected services are first.
  return !services_.empty() && services_.front()->IsConnected();
}

bool Manager::IsOnline() const {
  // |services_| is sorted such that online services are first.
  return !services_.empty() && services_.front()->IsOnline();
}

std::string Manager::CalculateState(Error* /*error*/) {
  return IsConnected() ? kStateOnline : kStateOffline;
}

void Manager::RefreshConnectionState() {
  const ServiceRefPtr& service = GetDefaultService();
  std::string connection_state =
      service ? service->GetStateString() : kStateIdle;
  if (connection_state_ == connection_state) {
    return;
  }
  connection_state_ = connection_state;
  adaptor_->EmitStringChanged(kConnectionStateProperty, connection_state_);
  // Send upstart notifications for the initial idle state
  // and when we transition in/out of connected states.
  if ((!is_connected_state_) && (IsConnected())) {
    is_connected_state_ = true;
    upstart_->NotifyConnected();
  } else if ((is_connected_state_) && (!IsConnected())) {
    is_connected_state_ = false;
    upstart_->NotifyDisconnected();
  } else if (connection_state_ == kStateIdle) {
    upstart_->NotifyDisconnected();
  }
}

std::vector<std::string> Manager::AvailableTechnologies(Error* /*error*/) {
  std::set<std::string> unique_technologies;
  for (const auto& device : devices_) {
    unique_technologies.insert(device->technology().GetName());
  }
  return std::vector<std::string>(unique_technologies.begin(),
                                  unique_technologies.end());
}

std::vector<std::string> Manager::ConnectedTechnologies(Error* /*error*/) {
  std::set<std::string> unique_technologies;
  for (const auto& device : devices_) {
    if (device->IsConnected())
      unique_technologies.insert(device->technology().GetName());
  }
  return std::vector<std::string>(unique_technologies.begin(),
                                  unique_technologies.end());
}

bool Manager::IsTechnologyConnected(Technology technology) const {
  for (const auto& device : devices_) {
    if (device->technology() == technology && device->IsConnected())
      return true;
  }
  return false;
}

std::string Manager::DefaultTechnology(Error* /*error*/) {
  return (!services_.empty() && services_[0]->IsConnected())
             ? services_[0]->GetTechnologyString()
             : "";
}

std::vector<std::string> Manager::EnabledTechnologies(Error* /*error*/) {
  std::set<std::string> unique_technologies;
  for (const auto& device : devices_) {
    if (device->enabled())
      unique_technologies.insert(device->technology().GetName());
  }
  return std::vector<std::string>(unique_technologies.begin(),
                                  unique_technologies.end());
}

std::vector<std::string> Manager::UninitializedTechnologies(Error* /*error*/) {
  return device_info_.GetUninitializedTechnologies();
}

RpcIdentifiers Manager::EnumerateProfiles(Error* /*error*/) {
  RpcIdentifiers profile_rpc_ids;
  for (const auto& profile : profiles_) {
    profile_rpc_ids.push_back(profile->GetRpcIdentifier());
  }
  return profile_rpc_ids;
}

RpcIdentifiers Manager::EnumerateAvailableServices(Error* /*error*/) {
  RpcIdentifiers service_rpc_ids;
  for (const auto& service : services_) {
    if (service->IsVisible()) {
      service_rpc_ids.push_back(service->GetRpcIdentifier());
    }
  }
  return service_rpc_ids;
}

RpcIdentifiers Manager::EnumerateCompleteServices(Error* /*error*/) {
  RpcIdentifiers service_rpc_ids;
  for (const auto& service : services_) {
    service_rpc_ids.push_back(service->GetRpcIdentifier());
  }
  return service_rpc_ids;
}

RpcIdentifiers Manager::EnumerateWatchedServices(Error* /*error*/) {
  RpcIdentifiers service_rpc_ids;
  watched_service_states_.clear();
  for (const auto& service : services_) {
    if (service->IsVisible() && service->IsActive(nullptr)) {
      service_rpc_ids.push_back(service->GetRpcIdentifier());
      watched_service_states_[service->serial_number()] = service->state();
    }
  }
  return service_rpc_ids;
}

RpcIdentifier Manager::GetActiveProfileRpcIdentifier(Error* /*error*/) {
  return ActiveProfile()->GetRpcIdentifier();
}

std::string Manager::GetCheckPortalList(Error* /*error*/) {
  return use_startup_portal_list_ ? startup_portal_list_
                                  : props_.check_portal_list;
}

bool Manager::SetCheckPortalList(const std::string& portal_list, Error* error) {
  use_startup_portal_list_ = false;
  if (props_.check_portal_list == portal_list) {
    return false;
  }
  props_.check_portal_list = portal_list;
  return true;
}

std::string Manager::GetIgnoredDNSSearchPaths(Error* /*error*/) {
  return props_.ignored_dns_search_paths;
}

bool Manager::SetIgnoredDNSSearchPaths(const std::string& ignored_paths,
                                       Error* /*error*/) {
  if (props_.ignored_dns_search_paths == ignored_paths) {
    return false;
  }
  std::vector<std::string> ignored_path_list;
  if (!ignored_paths.empty()) {
    ignored_path_list = base::SplitString(
        ignored_paths, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  }
  props_.ignored_dns_search_paths = ignored_paths;
  resolver_->set_ignored_search_list(ignored_path_list);
  return true;
}

std::string Manager::GetPortalFallbackUrlsString(Error* /*error*/) {
  return base::JoinString(props_.portal_fallback_http_urls, ",");
}

bool Manager::SetPortalFallbackUrlsString(const std::string& urls,
                                          Error* /*error*/) {
  if (urls.empty()) {
    return false;
  }
  auto url_list =
      base::SplitString(urls, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  props_.portal_fallback_http_urls = url_list;
  return true;
}

// called via RPC (e.g., from ManagerDBusAdaptor)
ServiceRefPtr Manager::GetService(const KeyValueStore& args, Error* error) {
  ServiceRefPtr service = GetServiceInner(args, error);
  if (service) {
    // Configures the service using the rest of the passed-in arguments.
    service->Configure(args, error);
  }

  return service;
}

ServiceRefPtr Manager::GetServiceInner(const KeyValueStore& args,
                                       Error* error) {
  if (args.Contains<std::string>(kGuidProperty)) {
    SLOG(this, 2) << __func__ << ": searching by GUID";
    ServiceRefPtr service =
        GetServiceWithGUID(args.Get<std::string>(kGuidProperty), nullptr);
    if (service) {
      return service;
    }
  }

  if (!args.Contains<std::string>(kTypeProperty)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          kErrorTypeRequired);
    return nullptr;
  }

  std::string type = args.Get<std::string>(kTypeProperty);
  Technology technology = Technology::CreateFromName(type);
  if (!base::Contains(providers_, technology)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kTechnologyNotAvailable,
        "Could not get service for technology: " + technology.GetName());
    return nullptr;
  }

  SLOG(this, 2) << __func__ << ": getting " << type << " Service";
  return providers_[technology]->GetService(args, error);
}

// called via RPC (e.g., from ManagerDBusAdaptor)
ServiceRefPtr Manager::ConfigureService(const KeyValueStore& args,
                                        Error* error) {
  ProfileRefPtr profile = ActiveProfile();
  bool profile_specified = args.Contains<std::string>(kProfileProperty);
  if (profile_specified) {
    std::string profile_rpcid(args.Get<std::string>(kProfileProperty));
    profile = LookupProfileByRpcIdentifier(profile_rpcid);
    if (!profile) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Invalid profile name " + profile_rpcid);
      return nullptr;
    }
  }

  ServiceRefPtr service = GetServiceInner(args, error);
  if (error->IsFailure() || !service) {
    LOG(ERROR) << "GetService failed; returning upstream error.";
    return nullptr;
  }

  // First pull in any stored configuration associated with the service.
  if (service->profile() == profile) {
    SLOG(this, 2) << __func__ << ": service " << service->log_name()
                  << " is already a member of profile "
                  << profile->GetFriendlyName()
                  << " so a load is not necessary.";
  } else if (profile->LoadService(service)) {
    SLOG(this, 2) << __func__ << ": applied stored information from profile "
                  << profile->GetFriendlyName() << " into service "
                  << service->log_name();
  } else {
    SLOG(this, 2) << __func__ << ": no previous information in profile "
                  << profile->GetFriendlyName() << " exists for service "
                  << service->log_name();
  }

  // Overlay this with the passed-in configuration parameters.
  service->Configure(args, error);

  // Overwrite the profile data with the resulting configured service.
  if (!profile->UpdateService(service)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Unable to save service to profile");
    return nullptr;
  }

  if (HasService(service)) {
    // If the service has been registered (it may not be -- as is the case
    // with invisible WiFi networks), we can now transfer the service between
    // profiles.
    if (IsServiceEphemeral(service) ||
        (profile_specified && service->profile() != profile)) {
      SLOG(this, 2) << "Moving service to profile "
                    << profile->GetFriendlyName();
      if (!MoveServiceToProfile(service, profile)) {
        Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                              "Unable to move service to profile");
      }
    }
  }

  // Notify the service that a profile has been configured for it.
  service->OnProfileConfigured();

  return service;
}

// called via RPC (e.g., from ManagerDBusAdaptor)
ServiceRefPtr Manager::ConfigureServiceForProfile(
    const std::string& profile_rpcid, const KeyValueStore& args, Error* error) {
  if (!args.Contains<std::string>(kTypeProperty)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          kErrorTypeRequired);
    return nullptr;
  }

  std::string type = args.Get<std::string>(kTypeProperty);
  Technology technology = Technology::CreateFromName(type);

  if (!base::Contains(providers_, technology)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kTechnologyNotAvailable,
        "Failed to configure service for technology: " + technology.GetName());
    return nullptr;
  }

  ProviderInterface* provider = providers_[technology];

  ProfileRefPtr profile = LookupProfileByRpcIdentifier(profile_rpcid);
  if (!profile) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "Profile specified was not found");
    return nullptr;
  }
  if (args.Lookup<std::string>(kProfileProperty, profile_rpcid) !=
      profile_rpcid) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Profile argument does not match that in "
                          "the configuration arguments");
    return nullptr;
  }

  ServiceRefPtr service = nullptr;
  // Non-Cellular Services are primarily identified by GUID. Cellular Services
  // are always identified by ICCID.
  if (type != kTypeCellular && args.Contains<std::string>(kGuidProperty)) {
    SLOG(this, 2) << __func__ << ": searching by GUID";
    service = GetServiceWithGUID(args.Get<std::string>(kGuidProperty), nullptr);
    if (service && service->technology() != technology) {
      Error::PopulateAndLog(
          FROM_HERE, error, Error::kInvalidArguments,
          base::StringPrintf("This GUID matches a non-%s service",
                             type.c_str()));
      return nullptr;
    }
  }

  if (!service) {
    Error find_error;
    service = provider->FindSimilarService(args, &find_error);
  }

  // If no matching service exists, create a new service in the specified
  // profile using ConfigureService().
  if (!service) {
    KeyValueStore configure_args;
    configure_args.CopyFrom(args);
    configure_args.Set<std::string>(kProfileProperty, profile_rpcid);
    return ConfigureService(configure_args, error);
  }

  // The service already exists and is set to the desired profile,
  // the service is in the ephemeral profile, or the current profile
  // for the service appears before the desired profile, we need to
  // reassign the service to the new profile if necessary, leaving
  // the old profile intact (i.e, not calling Profile::AbandonService()).
  // Then, configure the properties on the service as well as its newly
  // associated profile.
  if (service->profile() == profile || IsServiceEphemeral(service) ||
      IsProfileBefore(service->profile(), profile)) {
    SetupServiceInProfile(service, profile, args, error);
    return service;
  }

  // The current profile for the service appears after the desired
  // profile.  We must create a temporary service specifically for
  // the task of creating configuration data.  This service will
  // neither inherit properties from the visible service, nor will
  // it exist after this function returns.
  service = provider->CreateTemporaryService(args, error);
  if (!service || !error->IsSuccess()) {
    // Service::CreateTemporaryService() failed, and has set the error
    // appropriately.
    return nullptr;
  }

  // The profile may already have configuration for this service.
  profile->ConfigureService(service);

  SetupServiceInProfile(service, profile, args, error);

  // If we encountered an error when configuring the temporary service, we
  // report the error as it is. Otherwise, we still need to report an error as
  // the temporary service won't be usable by the caller.
  DCHECK(service->HasOneRef());
  if (error->IsSuccess()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "Temporary service configured but not usable");
  }
  return nullptr;
}

void Manager::SetupServiceInProfile(ServiceRefPtr service,
                                    ProfileRefPtr profile,
                                    const KeyValueStore& args,
                                    Error* error) {
  service->SetProfile(profile);
  service->Configure(args, error);
  profile->UpdateService(service);
}

ServiceRefPtr Manager::FindMatchingService(const KeyValueStore& args,
                                           Error* error) {
  for (const auto& service : services_) {
    if (service->DoPropertiesMatch(args)) {
      return service;
    }
  }
  error->Populate(Error::kNotFound, Error::kServiceNotFoundMsg, FROM_HERE);
  return nullptr;
}

DeviceRefPtr Manager::FindDeviceFromService(
    const ServiceRefPtr& service) const {
  if (!service) {
    return nullptr;
  }

  const auto virtual_device = service->GetVirtualDevice();
  if (virtual_device) {
    return virtual_device;
  }

  for (const auto& device : devices_) {
    if (device->selected_service() == service) {
      return device;
    }
  }
  return nullptr;
}

Connection* Manager::FindConnectionFromService(
    const ServiceRefPtr& service) const {
  if (!service || !service->HasActiveConnection()) {
    return nullptr;
  }
  auto device = FindDeviceFromService(service);
  if (!device) {
    return nullptr;
  }
  return device->connection();
}

ServiceRefPtr Manager::GetPrimaryPhysicalService() {
  // Note that |services_| is kept sorted in order of highest priority to
  // lowest.
  for (const auto& service : services_) {
    if (service->technology().IsPrimaryConnectivityTechnology()) {
      return service;
    }
  }
  return nullptr;
}

ServiceRefPtr Manager::GetFirstEthernetService() {
  for (const auto& service : services_) {
    if (service->technology() == Technology::kEthernet) {
      return service;
    }
  }
  return nullptr;
}

std::map<std::string, std::vector<GeolocationInfo>>
Manager::GetNetworksForGeolocation() const {
  std::map<std::string, std::vector<GeolocationInfo>> geolocation_infos;
  for (const auto& entry : device_geolocation_info_) {
    const DeviceRefPtr& device = entry.first;
    const std::vector<GeolocationInfo>& device_info = entry.second;
    std::vector<GeolocationInfo>* network_geolocation_info = nullptr;
    if (device->technology() == Technology::kWiFi) {
      network_geolocation_info =
          &geolocation_infos[kGeoWifiAccessPointsProperty];
    } else if (device->technology() == Technology::kCellular) {
      network_geolocation_info = &geolocation_infos[kGeoCellTowersProperty];
    } else {
      // Ignore other technologies.
      continue;
    }

    // Insert new info objects, but ensure that the last seen field is
    // replaced with an age field, if it exists.
    DCHECK(network_geolocation_info);
    std::transform(device_info.begin(), device_info.end(),
                   std::back_inserter(*network_geolocation_info),
                   &PrepareGeolocationInfoForExport);
  }

  return geolocation_infos;
}

void Manager::OnDeviceGeolocationInfoUpdated(const DeviceRefPtr& device) {
  SLOG(this, 2) << __func__ << " for device " << device->UniqueName();
  device_geolocation_info_[device] = device->GetGeolocationObjects();
}

void Manager::RecheckPortal(Error* /*error*/) {
  SLOG(this, 2) << __func__;
  for (const auto& device : devices_) {
    device->RequestPortalDetection();
  }
}

void Manager::RecheckPortalOnService(const ServiceRefPtr& service) {
  for (const auto& device : devices_) {
    if (device->IsConnectedToService(service)) {
      // As opposed to RecheckPortal() above, we explicitly stop and then
      // restart portal detection, since the service to recheck was explicitly
      // specified.
      device->RestartPortalDetection();
      break;
    }
  }
}

void Manager::RequestScan(const std::string& technology, Error* error) {
  Technology technology_identifier;
  // TODO(benchan): To maintain backward compatibility, we treat an unspecified
  // technology as WiFi. We should remove this special handling and treat an
  // unspecified technology as an error after we update existing clients of
  // this API to specify a valid technology when calling this method.
  if (technology.empty()) {
    technology_identifier = Technology::kWiFi;
  } else {
    technology_identifier = Technology::CreateFromName(technology);
  }

  switch (technology_identifier) {
    case Technology::kCellular:
      for (const auto& device : FilterByTechnology(technology_identifier)) {
        // TODO(benchan): Add a metric to track user-initiated scan for cellular
        // technology.
        device->Scan(error, __func__);
      }
      break;

    case Technology::kWiFi:
      for (const auto& device : FilterByTechnology(technology_identifier)) {
        device->Scan(error, __func__);
      }
      break;

    case Technology::kUnknown:
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Unrecognized technology " + technology);
      break;

    default:
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Scan unsupported for technology " + technology);
      break;
  }
}

std::string Manager::GetTechnologyOrder() {
  std::vector<std::string> technology_names;
  for (const auto& technology : technology_order_) {
    technology_names.push_back(technology.GetName());
  }

  return base::JoinString(technology_names, ",");
}

void Manager::SetTechnologyOrder(const std::string& order, Error* error) {
  std::vector<Technology> new_order;
  SLOG(this, 2) << "Setting technology order to " << order;
  if (!GetTechnologyVectorFromString(order, &new_order, error)) {
    return;
  }

  technology_order_ = new_order;
  if (running_) {
    SortServices();
  }
}

bool Manager::IsWifiIdle() {
  bool ret = false;

  // Since services are sorted by connection state, status of the wifi device
  // can be determine by examing the connection state of the first wifi service.
  for (const auto& service : services_) {
    if (service->technology() == Technology::kWiFi) {
      if (!service->IsConnecting() && !service->IsConnected()) {
        ret = true;
      }
      break;
    }
  }
  return ret;
}

void Manager::UpdateProviderMapping() {
#if !defined(DISABLE_CELLULAR)
  providers_[Technology::kCellular] = cellular_service_provider_.get();
#endif  // DISABLE_CELLULAR
  providers_[Technology::kEthernet] = ethernet_provider_.get();
#if !defined(DISABLE_WIRED_8021X)
  providers_[Technology::kEthernetEap] = ethernet_eap_provider_.get();
#endif  // DISABLE_WIRED_8021X
  providers_[Technology::kVPN] = vpn_provider_.get();
#if !defined(DISABLE_WIFI)
  providers_[Technology::kWiFi] = wifi_provider_.get();
#endif  // DISABLE_WIFI
}

std::vector<std::string> Manager::GetDeviceInterfaceNames() {
  std::vector<std::string> interfaces;

  for (const auto& device : devices_) {
    Technology technology = device->technology();
    if (technology.IsPrimaryConnectivityTechnology()) {
      interfaces.push_back(device->link_name());
      SLOG(this, 4) << "Adding device: " << device->link_name();
    }
  }
  return interfaces;
}

bool Manager::ShouldBlackholeUserTraffic(const std::string& device_name) const {
  if (!should_blackhole_user_traffic_) {
    return false;
  }
  for (const auto& device : devices_) {
    if (device->UniqueName() == device_name)
      return true;
  }
  return false;
}

void Manager::UpdateBlackholeUserTraffic() {
  bool before_update = should_blackhole_user_traffic_;
  if (props_.always_on_vpn_package.empty()) {
    should_blackhole_user_traffic_ = false;
  } else {
    should_blackhole_user_traffic_ = true;
    for (const auto& service : services_) {
      if (service->IsOnline() &&
          service->IsAlwaysOnVpn(props_.always_on_vpn_package)) {
        should_blackhole_user_traffic_ = false;
        break;
      }
    }
  }
  if (should_blackhole_user_traffic_ == before_update) {
    return;
  }
  for (const auto& device : devices_) {
    device->UpdateBlackholeUserTraffic();
  }
}

// static
std::vector<uint32_t> Manager::ComputeUserTrafficUids() {
  std::vector<uint32_t> uids;
  for (const auto& username : kUserTrafficUsernames) {
    uid_t uid;
    if (!brillo::userdb::GetUserInfo(username, &uid, nullptr)) {
      LOG(WARNING) << "Unable to look up UID for " << username;
      continue;
    }
    uids.push_back(static_cast<uint32_t>(uid));
  }
  return uids;
}

void Manager::InitializePatchpanelClient() {
  DCHECK(!patchpanel_client_);
  init_patchpanel_client_task_.Cancel();
  patchpanel_client_ = patchpanel::Client::New();
  if (!patchpanel_client_) {
    LOG(ERROR) << "Failed to connect to patchpanel client";
    init_patchpanel_client_task_.Reset(base::Bind(
        &Manager::InitializePatchpanelClient, weak_factory_.GetWeakPtr()));
    dispatcher_->PostDelayedTask(FROM_HERE,
                                 init_patchpanel_client_task_.callback(),
                                 kInitPatchpanelClientInterval);
    return;
  }

  // Kick off any patchpanel related communication below.
  device_info_.OnPatchpanelClientReady();

  // Start task for refreshing traffic counters.
  refresh_traffic_counter_task_.Reset(base::Bind(
      &Manager::RefreshAllTrafficCountersTask, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               refresh_traffic_counter_task_.callback(),
                               kTrafficCounterRefreshInterval);

  // Ensure that VPN lockdown starts if needed.
  std::string always_on_vpn_mode = always_on_vpn_mode_;
  always_on_vpn_mode_ = kAlwaysOnVpnModeOff;
  SetAlwaysOnVpn(always_on_vpn_mode, always_on_vpn_service_);
}

void Manager::RefreshAllTrafficCountersCallback(
    const std::vector<patchpanel::TrafficCounter>& counters) {
  std::map<std::string, std::vector<patchpanel::TrafficCounter>> counter_map;
  for (const auto& counter : counters) {
    std::string link_name = counter.device();
    counter_map[link_name].push_back(counter);
  }
  for (const auto& device : devices_) {
    if (device->selected_service()) {
      device->selected_service()->RefreshTrafficCounters(
          counter_map[device->link_name()]);
    }
  }
  pending_traffic_counter_request_ = false;
}

void Manager::RefreshAllTrafficCountersTask() {
  SLOG(this, 2) << __func__;
  refresh_traffic_counter_task_.Reset(base::Bind(
      &Manager::RefreshAllTrafficCountersTask, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               refresh_traffic_counter_task_.callback(),
                               kTrafficCounterRefreshInterval);

  if (pending_traffic_counter_request_) {
    return;
  }

  patchpanel::Client* client = patchpanel_client();
  if (!client) {
    return;
  }
  pending_traffic_counter_request_ = true;
  client->GetTrafficCounters(
      std::set<std::string>() /* all devices */,
      base::BindOnce(&Manager::RefreshAllTrafficCountersCallback,
                     weak_factory_.GetWeakPtr()));
}

std::string Manager::GetAlwaysOnVpnPackage(Error* /*error*/) {
  return props_.always_on_vpn_package;
}

bool Manager::SetAlwaysOnVpnPackage(const std::string& package_name,
                                    Error* error) {
  if (props_.always_on_vpn_package == package_name)
    return false;
  props_.always_on_vpn_package = package_name;
  UpdateBlackholeUserTraffic();
  return true;
}

bool Manager::SetDNSProxyAddresses(const std::vector<std::string>& addrs,
                                   Error* error) {
  if (props_.dns_proxy_addresses == addrs)
    return false;

  if (addrs.empty()) {
    ClearDNSProxyAddresses();
    return true;
  }

  for (const auto& addr : addrs) {
    struct in_addr p_addr4;
    if (inet_pton(AF_INET, addr.c_str(), &p_addr4) == 1) {
      // Verify proxy's IPv4 address.
      if ((p_addr4.s_addr & kDNSProxyNetmask.s_addr) ==
          kDNSProxyBaseAddr.s_addr) {
        continue;
      }
      ClearDNSProxyAddresses();
      LOG(ERROR) << "IPv4 DNS proxy address " << addr
                 << " is not allowed, cleared DNS proxy address(es)";
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidProperty,
                            "Address not allowed: " + addr);
      return false;
    }

    struct in6_addr p_addr6;
    if (inet_pton(AF_INET6, addr.c_str(), &p_addr6) != 1) {
      ClearDNSProxyAddresses();
      LOG(ERROR) << "DNS proxy address " << addr
                 << " is not valid, cleared DNS proxy address(es)";
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Invalid address: " + addr);
      return false;
    }
  }

  props_.dns_proxy_addresses = addrs;

  // Assign the dns-proxy addresses on the Resolver;
  // existing DNS configuration for the connection will be preserved.
  // Only pass the nameservers to the resolver if the default service is online.
  // UpdateDefaultService will propagate the change when the service comes
  // online.
  if (last_default_physical_service_online_) {
    UseDNSProxy(props_.dns_proxy_addresses);
  }
  return true;
}

void Manager::ClearDNSProxyAddresses() {
  props_.dns_proxy_addresses.clear();
  UseDNSProxy({});
}

void Manager::UseDNSProxy(const std::vector<std::string>& proxy_addrs) {
  if (!running_)
    return;

  resolver_->SetDNSProxyAddresses(proxy_addrs);
}

KeyValueStore Manager::GetDNSProxyDOHProviders(Error* /* error */) {
  return props_.dns_proxy_doh_providers;
}

bool Manager::SetDNSProxyDOHProviders(const KeyValueStore& providers,
                                      Error* error) {
  if (error)
    error->Reset();

  if (providers == props_.dns_proxy_doh_providers)
    return false;

  for (const auto& [url, nameservers] : providers.properties()) {
    if (!HttpUrl().ParseFromString(url)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "Invalid URL: " + url);
      return false;
    }
    for (const auto& ns :
         base::SplitString(nameservers.TryGet<std::string>(""), ",",
                           base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
      if (!IPAddress(ns).IsValid()) {
        Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                              "Invalid address: " + ns);
        return false;
      }
    }
  }

  props_.dns_proxy_doh_providers = providers;
  adaptor_->EmitKeyValueStoreChanged(kDNSProxyDOHProvidersProperty,
                                     props_.dns_proxy_doh_providers);
  return true;
}

bool Manager::AddPasspointCredentials(const std::string& profile_rpcid,
                                      const KeyValueStore& properties,
                                      Error* error) {
  if (error)
    error->Reset();

#if !defined(DISABLE_WIFI)
  ProfileRefPtr profile = LookupProfileByRpcIdentifier(profile_rpcid);
  if (!profile) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "Profile " + profile_rpcid + " not found");
    return false;
  }
  if (profile->IsDefault()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Can't add credentials to default profile");
    return false;
  }

  PasspointCredentialsRefPtr creds =
      PasspointCredentials::CreatePasspointCredentials(properties, error);
  if (!creds) {
    // We expect |error| to be filled by the Passpoint credentials "factory".
    LOG(ERROR) << "failed to create Passpoint credentials";
    return false;
  }

  if (!profile->AdoptCredentials(creds)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        "failed to save credentials to profile " + profile_rpcid);
    return false;
  }

  wifi_provider_->AddCredentials(creds);

  return true;
#else
  Error::PopulateAndLog(FROM_HERE, error, Error::kNotImplemented,
                        "Passpoint requires Wi-Fi support");
  return false;
#endif  // !DISABLE_WIFI
}

bool Manager::RemovePasspointCredentials(const std::string& profile_rpcid,
                                         const KeyValueStore& properties,
                                         Error* error) {
  if (error)
    error->Reset();

#if !defined(DISABLE_WIFI)
  ProfileRefPtr profile = LookupProfileByRpcIdentifier(profile_rpcid);
  if (!profile) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "Profile " + profile_rpcid + " not found");
    return false;
  }
  if (profile->IsDefault()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Can't remove credentials from default profile");
    return false;
  }

  if (!wifi_provider_->ForgetCredentials(properties)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Failed to remove Passpoint credentials");
    return false;
  }
  return true;
#else
  Error::PopulateAndLog(FROM_HERE, error, Error::kNotImplemented,
                        "Passpoint requires Wi-Fi support");
  return false;
#endif  // !DISABLE_WIFI
}

bool Manager::SetNetworkThrottlingStatus(const ResultCallback& callback,
                                         bool enabled,
                                         uint32_t upload_rate_kbits,
                                         uint32_t download_rate_kbits) {
  SLOG(this, 2) << __func__;

  LOG(INFO) << "Received command for network throttling "
            << (enabled ? "enabling" : "disabling");

  bool result = false;

  network_throttling_enabled_ = enabled;

  if (enabled) {
    upload_rate_kbits_ = upload_rate_kbits;
    download_rate_kbits_ = download_rate_kbits;

    LOG(INFO) << "Asked for upload rate (kbits/s) : " << upload_rate_kbits_
              << " download rate (kbits/s) : " << download_rate_kbits_;
    result = throttler_->ThrottleInterfaces(callback, upload_rate_kbits_,
                                            download_rate_kbits_);
  } else {
    result = throttler_->DisableThrottlingOnAllInterfaces(callback);
  }
  return result;
}

DeviceRefPtr Manager::GetDeviceConnectedToService(ServiceRefPtr service) {
  for (DeviceRefPtr device : devices_) {
    if (device->IsConnectedToService(service)) {
      return device;
    }
  }
  return nullptr;
}

void Manager::DetectMultiHomedDevices() {
  std::map<std::string, std::vector<DeviceRefPtr>> subnet_buckets;
  for (const auto& device : devices_) {
    const auto& connection = device->connection();
    std::string subnet_name;
    if (connection) {
      subnet_name = connection->GetSubnetName();
    }
    if (subnet_name.empty()) {
      device->SetIsMultiHomed(false);
    } else {
      subnet_buckets[subnet_name].push_back(device);
    }
  }

  for (const auto& subnet_bucket : subnet_buckets) {
    const auto& device_list = subnet_bucket.second;
    if (device_list.size() > 1) {
      for (const auto& device : device_list) {
        device->SetIsMultiHomed(true);
      }
    } else {
      DCHECK_EQ(1U, device_list.size());
      device_list.back()->SetIsMultiHomed(false);
    }
  }
}

bool Manager::GetUseSwanctlDriver(Error* error) {
  if (props_.use_swanctl_driver.has_value()) {
    return props_.use_swanctl_driver.value();
  }
  // Default is using the new driver.
  return true;
}

bool Manager::SetUseSwanctlDriver(const bool& use_swanctl_driver,
                                  Error* error) {
  props_.use_swanctl_driver = use_swanctl_driver;
  return true;
}

const std::vector<uint32_t>& Manager::GetUserTrafficUids() {
  if (user_traffic_uids_.empty()) {
    user_traffic_uids_ = ComputeUserTrafficUids();
  }
  return user_traffic_uids_;
}

}  // namespace shill
