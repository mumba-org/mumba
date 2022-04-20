// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi.h"

#include <inttypes.h>
#include <linux/if.h>  // Needs definitions from netinet/ether.h
#include <linux/nl80211.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
//#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/numerics/safe_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/control_interface.h"
#include "shill/dbus/dbus_control.h"
#include "shill/device.h"
#include "shill/eap_credentials.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/ieee80211.h"
#include "shill/net/ip_address.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/netlink_message.h"
#include "shill/net/nl80211_message.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/shill_time.h"
#include "shill/network/dhcp_controller.h"
#include "shill/scope_logger.h"
#include "shill/store/property_accessor.h"
#include "shill/supplicant/supplicant_eap_state_handler.h"
#include "shill/supplicant/supplicant_interface_proxy_interface.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/supplicant/supplicant_network_proxy_interface.h"
#include "shill/supplicant/supplicant_process_proxy_interface.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wake_on_wifi.h"
#include "shill/wifi/wifi_cqm.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_provider.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
static std::string ObjectID(const WiFi* w) {
  return w->GetRpcIdentifier().value();
}
}  // namespace Logging

// statics
const char* const WiFi::kDefaultBgscanMethod =
    WPASupplicant::kNetworkBgscanMethodSimple;
const uint16_t WiFi::kDefaultScanIntervalSeconds = 60;

// Scan interval while connected.
const uint16_t WiFi::kBackgroundScanIntervalSeconds = 360;
// Default background scan interval when there is only one endpoint on the
// network. We'd like to strike a balance between 1) not triggering too
// frequently with poor signal, 2) hardly triggering at all with good signal,
// and 3) being able to discover additional APs that weren't initially visible.
const int WiFi::kSingleEndpointBgscanIntervalSeconds = 86400;
// Age (in seconds) beyond which a BSS cache entry will not be preserved,
// across a suspend/resume.
const time_t WiFi::kMaxBSSResumeAgeSeconds = 10;
const char WiFi::kInterfaceStateUnknown[] = "shill-unknown";
const int WiFi::kNumFastScanAttempts = 3;
const uint32_t WiFi::kDefaultWiphyIndex = UINT32_MAX;

// The default random MAC mask is FF:FF:FF:00:00:00. Bits which are a 1 in
// the mask stay the same during randomization, and bits which are 0 are
// randomized. This mask means the OUI will remain unchanged but the last
// three octets will be different.
const std::vector<unsigned char> WiFi::kRandomMacMask{255, 255, 255, 0, 0, 0};

const char WiFi::kWakeOnWiFiNotSupported[] = "Wake on WiFi not supported";

namespace {
const uint16_t kDefaultBgscanShortIntervalSeconds = 64;
const uint16_t kSingleEndpointBgscanShortIntervalSeconds = 360;
const int32_t kDefaultBgscanSignalThresholdDbm = -72;
// Delay between scans when supplicant finds "No suitable network".
const time_t kRescanIntervalSeconds = 1;
const base::TimeDelta kPendingTimeout = base::Seconds(15);
const int kMaxRetryCreateInterfaceAttempts = 6;
const base::TimeDelta kRetryCreateInterfaceInterval = base::Seconds(10);
const int16_t kDefaultDisconnectDbm = 0;
const int16_t kDefaultDisconnectThresholdDbm = -75;
const int kInvalidMaxSSIDs = -1;

// Maximum time between two link monitor failures to declare this link (network)
// as unreliable.
constexpr auto kLinkUnreliableThreshold = base::Minutes(60);
// Mark a unreliable service as reliable if no more link monitor failures in
// the below timeout after this unreliable service became connected again.
constexpr auto kLinkUnreliableResetTimeout = base::Minutes(5);

bool IsPrintableAsciiChar(char c) {
  return (c >= ' ' && c <= '~');
}

// Is the state of wpa_supplicant indicating that it is currently possibly
// attempting to connect to a network (e.g. is it associating?).
bool IsWPAStateConnectionInProgress(const std::string& state) {
  return state == WPASupplicant::kInterfaceStateAuthenticating ||
         state == WPASupplicant::kInterfaceStateAssociating ||
         state == WPASupplicant::kInterfaceStateAssociated ||
         state == WPASupplicant::kInterfaceState4WayHandshake ||
         state == WPASupplicant::kInterfaceStateGroupHandshake;
}

}  // namespace

WiFi::WiFi(Manager* manager,
           const std::string& link,
           const std::string& address,
           int interface_index,
           std::unique_ptr<WakeOnWiFiInterface> wake_on_wifi)
    : Device(manager, link, address, interface_index, Technology::kWiFi),
      provider_(manager->wifi_provider()),
      time_(Time::GetInstance()),
      supplicant_connect_attempts_(0),
      supplicant_present_(false),
      supplicant_state_(kInterfaceStateUnknown),
      supplicant_bss_(RpcIdentifier("(unknown)")),
      supplicant_assoc_status_(IEEE_80211::kStatusCodeSuccessful),
      supplicant_auth_status_(IEEE_80211::kStatusCodeSuccessful),
      supplicant_disconnect_reason_(IEEE_80211::kReasonCodeInvalid),
      disconnect_signal_dbm_(kDefaultDisconnectDbm),
      disconnect_threshold_dbm_(kDefaultDisconnectThresholdDbm),
      max_ssids_per_scan_(kInvalidMaxSSIDs),
      supplicant_auth_mode_(WPASupplicant::kAuthModeUnknown),
      need_bss_flush_(false),
      resumed_at_((struct timeval){0}),
      fast_scans_remaining_(kNumFastScanAttempts),
      has_already_completed_(false),
      is_roaming_in_progress_(false),
      pending_eap_failure_(Service::kFailureNone),
      is_debugging_connection_(false),
      eap_state_handler_(new SupplicantEAPStateHandler()),
      ipv4_gateway_found_(false),
      ipv6_gateway_found_(false),
      last_link_monitor_failed_time_(0),
      bgscan_short_interval_seconds_(kDefaultBgscanShortIntervalSeconds),
      bgscan_signal_threshold_dbm_(kDefaultBgscanSignalThresholdDbm),
      scan_interval_seconds_(kDefaultScanIntervalSeconds),
      netlink_manager_(NetlinkManager::GetInstance()),
      random_mac_supported_(false),
      random_mac_enabled_(false),
      sched_scan_supported_(false),
      scan_state_(kScanIdle),
      scan_method_(kScanMethodNone),
      broadcast_probe_was_skipped_(false),
      interworking_select_enabled_(false),
      hs20_bss_count_(0),
      need_interworking_select_(false),
      receive_byte_count_at_connect_(0),
      wiphy_index_(kDefaultWiphyIndex),
      wifi_cqm_(new WiFiCQM(metrics(), this)),
      wake_on_wifi_(std::move(wake_on_wifi)),
      weak_ptr_factory_while_started_(this),
      weak_ptr_factory_(this) {
  scoped_supplicant_listener_.reset(
      new SupplicantManager::ScopedSupplicantListener(
          manager->supplicant_manager(),
          base::Bind(&WiFi::OnSupplicantPresence,
                     weak_ptr_factory_.GetWeakPtr())));

  PropertyStore* store = this->mutable_store();
  store->RegisterDerivedString(
      kBgscanMethodProperty,
      StringAccessor(new CustomAccessor<WiFi, std::string>(
          this, &WiFi::GetBgscanMethod, &WiFi::SetBgscanMethod,
          &WiFi::ClearBgscanMethod)));
  HelpRegisterDerivedUint16(store, kBgscanShortIntervalProperty,
                            &WiFi::GetBgscanShortInterval,
                            &WiFi::SetBgscanShortInterval);
  HelpRegisterDerivedInt32(store, kBgscanSignalThresholdProperty,
                           &WiFi::GetBgscanSignalThreshold,
                           &WiFi::SetBgscanSignalThreshold);
  store->RegisterConstBool(kMacAddressRandomizationSupportedProperty,
                           &random_mac_supported_);
  HelpRegisterDerivedBool(store, kMacAddressRandomizationEnabledProperty,
                          &WiFi::GetRandomMacEnabled,
                          &WiFi::SetRandomMacEnabled);

  store->RegisterDerivedKeyValueStore(
      kLinkStatisticsProperty,
      KeyValueStoreAccessor(new CustomAccessor<WiFi, KeyValueStore>(
          this, &WiFi::GetLinkStatistics, nullptr)));

  // TODO(quiche): Decide if scan_pending_ is close enough to
  // "currently scanning" that we don't care, or if we want to track
  // scan pending/currently scanning/no scan scheduled as a tri-state
  // kind of thing.
  HelpRegisterConstDerivedBool(store, kScanningProperty, &WiFi::GetScanPending);
  HelpRegisterConstDerivedUint16s(store, kWifiSupportedFrequenciesProperty,
                                  &WiFi::GetAllScanFrequencies);
  HelpRegisterDerivedUint16(store, kScanIntervalProperty,
                            &WiFi::GetScanInterval, &WiFi::SetScanInterval);
  HelpRegisterConstDerivedBool(store, kWakeOnWiFiSupportedProperty,
                               &WiFi::GetWakeOnWiFiSupported);

  HelpRegisterDerivedBool(store, kPasspointInterworkingSelectEnabledProperty,
                          &WiFi::GetInterworkingSelectEnabled,
                          &WiFi::SetInterworkingSelectEnabled);

  if (wake_on_wifi_) {
    wake_on_wifi_->InitPropertyStore(store);
  }
  ScopeLogger::GetInstance()->RegisterScopeEnableChangedCallback(
      ScopeLogger::kWiFi, base::Bind(&WiFi::OnWiFiDebugScopeChanged,
                                     weak_ptr_factory_.GetWeakPtr()));
  CHECK(netlink_manager_);
  netlink_handler_ =
      base::Bind(&WiFi::HandleNetlinkBroadcast, weak_ptr_factory_.GetWeakPtr());
  netlink_manager_->AddBroadcastHandler(netlink_handler_);
  SLOG(this, 2) << "WiFi device " << link_name() << " initialized.";
}

WiFi::~WiFi() {
  netlink_manager_->RemoveBroadcastHandler(netlink_handler_);
}

void WiFi::Start(Error* error,
                 const EnabledStateChangedCallback& /*callback*/) {
  SLOG(this, 2) << "WiFi " << link_name() << " starting.";
  if (enabled()) {
    return;
  }
  Metrics::WiFiAdapterInfo hw_info{
      .vendor_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .product_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .subsystem_id = Metrics::kWiFiStructuredMetricsErrorValue};
  GetDeviceHardwareIds(&hw_info.vendor_id, &hw_info.product_id,
                       &hw_info.subsystem_id);
  metrics()->NotifyWiFiAdapterStateChanged(true, hw_info);
  OnEnabledStateChanged(EnabledStateChangedCallback(), Error());
  if (error) {
    error->Reset();  // indicate immediate completion
  }

  // Subscribe to multicast events.
  netlink_manager_->SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                      NetlinkManager::kEventTypeConfig);
  netlink_manager_->SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                      NetlinkManager::kEventTypeScan);
  netlink_manager_->SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                      NetlinkManager::kEventTypeRegulatory);
  netlink_manager_->SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                      NetlinkManager::kEventTypeMlme);
  GetPhyInfo();
  // Connect to WPA supplicant if it's already present. If not, we'll connect to
  // it when it appears.
  supplicant_connect_attempts_ = 0;
  ConnectToSupplicant();
  if (wake_on_wifi_) {
    wake_on_wifi_->Start();
  }
}

void WiFi::Stop(Error* error, const EnabledStateChangedCallback& /*callback*/) {
  SLOG(this, 2) << "WiFi " << link_name() << " stopping.";
  // Unlike other devices, we leave the DBus name watcher in place here, because
  // WiFi callbacks expect notifications even if the device is disabled.
  Metrics::WiFiAdapterInfo hw_info{
      .vendor_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .product_id = Metrics::kWiFiStructuredMetricsErrorValue,
      .subsystem_id = Metrics::kWiFiStructuredMetricsErrorValue};
  GetDeviceHardwareIds(&hw_info.vendor_id, &hw_info.product_id,
                       &hw_info.subsystem_id);
  metrics()->NotifyWiFiAdapterStateChanged(false, hw_info);
  DropConnection();
  StopScanTimer();
  for (const auto& endpoint : endpoint_by_rpcid_) {
    provider_->OnEndpointRemoved(endpoint.second);
  }
  endpoint_by_rpcid_.clear();
  for (const auto& map_entry : rpcid_by_service_) {
    RemoveNetwork(map_entry.second);
  }
  rpcid_by_service_.clear();
  // Remove all the credentials registered in supplicant.
  for (const auto& creds : provider_->GetCredentials()) {
    RemoveCred(creds);
  }
  pending_matches_.clear();
  hs20_bss_count_ = 0;
  need_interworking_select_ = false;
  // Remove interface from supplicant.
  if (supplicant_present_ && supplicant_interface_proxy_) {
    supplicant_process_proxy()->RemoveInterface(supplicant_interface_path_);
  }
  pending_scan_results_.reset();
  current_service_ = nullptr;  // breaks a reference cycle
  pending_service_ = nullptr;  // breaks a reference cycle
  is_debugging_connection_ = false;
  SetScanState(kScanIdle, kScanMethodNone, __func__);
  StopPendingTimer();
  StopReconnectTimer();
  StopRequestingStationInfo();

  OnEnabledStateChanged(EnabledStateChangedCallback(), Error());
  if (error)
    error->Reset();  // indicate immediate completion
  weak_ptr_factory_while_started_.InvalidateWeakPtrs();

  SLOG(this, 3) << "WiFi " << link_name() << " supplicant_interface_proxy_ "
                << (supplicant_interface_proxy_.get() ? "is set."
                                                      : "is not set.");
  SLOG(this, 3) << "WiFi " << link_name() << " pending_service_ "
                << (pending_service_.get() ? "is set." : "is not set.");
  SLOG(this, 3) << "WiFi " << link_name() << " has "
                << endpoint_by_rpcid_.size() << " EndpointMap entries.";
}

void WiFi::Scan(Error* /*error*/, const std::string& reason) {
  if ((scan_state_ != kScanIdle) ||
      (current_service_.get() && current_service_->IsConnecting())) {
    SLOG(this, 2) << "Ignoring scan request while scanning or connecting.";
    return;
  }
  SLOG(this, 1) << __func__ << " on " << link_name() << " from " << reason;
  // Needs to send a D-Bus message, but may be called from D-Bus
  // signal handler context (via Manager::RequestScan). So defer work
  // to event loop.
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::ScanTask,
                                weak_ptr_factory_while_started_.GetWeakPtr()));
}

int16_t WiFi::GetSignalLevelForActiveService() {
  return current_service_ ? current_service_->SignalLevel()
                          : WiFiService::SignalLevelMin;
}

bool WiFi::AddCred(const PasspointCredentialsRefPtr& credentials) {
  SLOG(this, 2) << __func__;
  CHECK(credentials);

  if (!supplicant_present_ || !enabled()) {
    // Supplicant is not here yet, the credentials will be pushed later.
    credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());
    return false;
  }

  RpcIdentifier id;
  KeyValueStore properties;
  if (!credentials->ToSupplicantProperties(&properties)) {
    LOG(ERROR) << "failed to get supplicant properties from passpoint "
               << "credentials " << credentials->id();
    return false;
  }
  if (!supplicant_interface_proxy_->AddCred(properties, &id)) {
    LOG(ERROR) << "failed add passpoint credentials " << credentials->id()
               << " to supplicant";
    credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());
    return false;
  }
  credentials->SetSupplicantId(id);
  // There's a new credentials set, we'll need to try matching them.
  need_interworking_select_ = true;
  return true;
}

bool WiFi::RemoveCred(const PasspointCredentialsRefPtr& credentials) {
  SLOG(this, 2) << __func__;
  CHECK(credentials);

  if (!supplicant_present_ || !enabled()) {
    // Supplicant is not here, there's not credentials to remove.
    // Just invalidate the path.
    credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());
    return false;
  }

  if (credentials->supplicant_id() == DBusControl::NullRpcIdentifier()) {
    LOG(ERROR) << "credentials " << credentials->id()
               << " not registered in supplicant.";
    return false;
  }

  RpcIdentifier id(credentials->supplicant_id());
  credentials->SetSupplicantId(DBusControl::NullRpcIdentifier());

  if (!supplicant_interface_proxy_->RemoveCred(id)) {
    // The only reason for a failure here would be an invalid D-Bus path.
    LOG(ERROR) << "failed to remove credentials " << credentials->id()
               << " from supplicant with path " << id.value();
    return false;
  }
  return true;
}

void WiFi::EnsureScanAndConnectToBestService(Error* error) {
  // If the radio is currently idle, start a scan.  Otherwise, wait until the
  // radio becomes idle.
  if (scan_state_ == kScanIdle) {
    ensured_scan_state_ = EnsuredScanState::kScanning;
    Scan(error, "Starting ensured scan.");
  } else {
    ensured_scan_state_ = EnsuredScanState::kWaiting;
  }
}

void WiFi::AddPendingScanResult(const RpcIdentifier& path,
                                const KeyValueStore& properties,
                                bool is_removal) {
  // BSS events might come immediately after Stop(). Don't bother stashing them
  // at all.
  if (!enabled()) {
    return;
  }

  if (!pending_scan_results_) {
    pending_scan_results_.reset(new PendingScanResults(
        base::Bind(&WiFi::PendingScanResultsHandler,
                   weak_ptr_factory_while_started_.GetWeakPtr())));
    dispatcher()->PostTask(FROM_HERE,
                           pending_scan_results_->callback.callback());
  }
  pending_scan_results_->results.emplace_back(path, properties, is_removal);
}

void WiFi::BSSAdded(const RpcIdentifier& path,
                    const KeyValueStore& properties) {
  // Called from a D-Bus signal handler, and may need to send a D-Bus
  // message. So defer work to event loop.
  AddPendingScanResult(path, properties, false);
}

void WiFi::BSSRemoved(const RpcIdentifier& path) {
  // Called from a D-Bus signal handler, and may need to send a D-Bus
  // message. So defer work to event loop.
  AddPendingScanResult(path, {}, true);
}

void WiFi::Certification(const KeyValueStore& properties) {
  dispatcher()->PostTask(
      FROM_HERE,
      base::BindOnce(&WiFi::CertificationTask,
                     weak_ptr_factory_while_started_.GetWeakPtr(), properties));
}

void WiFi::EAPEvent(const std::string& status, const std::string& parameter) {
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::EAPEventTask,
                                weak_ptr_factory_while_started_.GetWeakPtr(),
                                status, parameter));
}

void WiFi::PropertiesChanged(const KeyValueStore& properties) {
  SLOG(this, 2) << __func__;
  // Called from D-Bus signal handler, but may need to send a D-Bus
  // message. So defer work to event loop.
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::PropertiesChangedTask,
                                weak_ptr_factory_.GetWeakPtr(), properties));
}

void WiFi::ScanDone(const bool& success) {
  // This log line should be kept at INFO level to support the Shill log
  // processor.
  LOG(INFO) << __func__;

  if (!enabled()) {
    SLOG(this, 2) << "Ignoring scan completion while disabled";
    return;
  }

  // Defer handling of scan result processing, because that processing
  // may require the the registration of new D-Bus objects. And such
  // registration can't be done in the context of a D-Bus signal
  // handler.
  if (pending_scan_results_) {
    pending_scan_results_->is_complete = true;
    return;
  }
  if (success) {
    scan_failed_callback_.Cancel();
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(&WiFi::ScanDoneTask,
                       weak_ptr_factory_while_started_.GetWeakPtr()));
  } else {
    scan_failed_callback_.Reset(base::Bind(
        &WiFi::ScanFailedTask, weak_ptr_factory_while_started_.GetWeakPtr()));
    dispatcher()->PostDelayedTask(FROM_HERE, scan_failed_callback_.callback(),
                                  kPostScanFailedDelay);
  }
}

void WiFi::InterworkingAPAdded(const RpcIdentifier& BSS,
                               const RpcIdentifier& cred,
                               const KeyValueStore& properties) {
  SLOG(this, 2) << __func__;

  if (!enabled()) {
    // Ignore spurious match events emitted after Stop().
    SLOG(this, 2) << "Ignoring interworking matches while being disabled.";
    return;
  }

  // Add the new match to the list. It'll be processed when the whole matching
  // sequence will be finished.
  pending_matches_.emplace_back(BSS, cred, properties);
}

void WiFi::InterworkingSelectDone() {
  SLOG(this, 2) << __func__;

  if (!enabled()) {
    SLOG(this, 2) << "Ignoring interworking done while being disabled.";
    return;
  }

  if (pending_matches_.empty()) {
    // No matches, nothing to do.
    return;
  }

  // Ensure credentials are available through their supplicant identifier.
  std::map<RpcIdentifier, PasspointCredentialsRefPtr> creds_by_rpcid;
  for (const auto& c : provider_->GetCredentials()) {
    creds_by_rpcid[c->supplicant_id()] = c;
  }

  // Translate each interworking match to a credential match by finding the
  // real references behind supplicant ids. Some credentials set or BSS might
  // be missing because they can be removed while the selection is in progress,
  // in such case the match is ignored.
  std::vector<WiFiProvider::PasspointMatch> matches;
  for (const auto& m : pending_matches_) {
    PasspointCredentialsRefPtr creds = creds_by_rpcid[m.cred_path];
    if (!creds) {
      LOG(WARNING) << "Passpoint credentials not found: "
                   << m.cred_path.value();
      continue;
    }

    WiFiEndpointRefPtr endpoint = endpoint_by_rpcid_[m.bss_path];
    if (!endpoint) {
      LOG(WARNING) << "endpoint not found: " << m.bss_path.value();
      continue;
    }

    const std::string type_str =
        m.properties.Get<std::string>(WPASupplicant::kCredentialsMatchType);
    WiFiProvider::MatchPriority type = WiFiProvider::MatchPriority::kUnknown;
    if (type_str == WPASupplicant::kCredentialsMatchTypeHome) {
      type = WiFiProvider::MatchPriority::kHome;
    } else if (type_str == WPASupplicant::kCredentialsMatchTypeRoaming) {
      type = WiFiProvider::MatchPriority::kRoaming;
    } else if (type_str == WPASupplicant::kCredentialsMatchTypeUnknown) {
      type = WiFiProvider::MatchPriority::kUnknown;
    } else {
      NOTREACHED() << __func__ << " unknown match type: " << type_str;
    }

    matches.emplace_back(creds, endpoint, type);
  }
  pending_matches_.clear();
  if (!matches.empty()) {
    provider_->OnPasspointCredentialsMatches(std::move(matches));
  }
}

void WiFi::ConnectTo(WiFiService* service, Error* error) {
  CHECK(service) << "Can't connect to NULL service.";
  RpcIdentifier network_rpcid;

  // Ignore this connection attempt if suppplicant is not present.
  // This is possible when we try to connect right after WiFi
  // boostrapping is completed (through weaved). Refer to b/24605760
  // for more information.
  // Once supplicant is detected, shill will auto-connect to this
  // service (if this service is configured for auto-connect) when
  // it is discovered in the scan.
  if (!supplicant_present_) {
    LOG(WARNING) << "Trying to connect before supplicant is present";
    return;
  }

  // TODO(quiche): Handle cases where already connected.
  if (pending_service_ && pending_service_ == service) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInProgress,
        base::StringPrintf(
            "%s: ignoring ConnectTo %s, which is already pending",
            link_name().c_str(), service->log_name().c_str()));
    return;
  }

  if (pending_service_ && pending_service_ != service) {
    LOG(INFO) << "Connecting to: " << service->log_name() << ", "
              << "mode: " << service->mode() << ", "
              << "key management: " << service->key_management() << ", "
              << "physical mode: " << service->physical_mode() << ", "
              << "frequency: " << service->frequency();
    // This is a signal to SetPendingService(nullptr) to not modify the scan
    // state since the overall story arc isn't reflected by the disconnect.
    // It is, instead, described by the transition to either kScanFoundNothing
    // or kScanConnecting (made by |SetPendingService|, below).
    if (scan_method_ != kScanMethodNone) {
      SetScanState(kScanTransitionToConnecting, scan_method_, __func__);
    }
    // Explicitly disconnect pending service.
    pending_service_->set_expecting_disconnect(true);
    DisconnectFrom(pending_service_.get());
  }

  Error unused_error;
  network_rpcid = FindNetworkRpcidForService(service, &unused_error);
  const auto [new_mac, update_supplicant] = service->UpdateMACAddress();
  if (network_rpcid.value().empty()) {
    KeyValueStore service_params =
        service->GetSupplicantConfigurationParameters();
    const uint32_t scan_ssid = 1;  // "True": Use directed probe.
    service_params.Set<uint32_t>(WPASupplicant::kNetworkPropertyScanSSID,
                                 scan_ssid);
    std::string bgscan_string = AppendBgscan(service, &service_params);
    service_params.Set<uint32_t>(WPASupplicant::kNetworkPropertyDisableVHT,
                                 provider_->disable_vht());
    if (!supplicant_interface_proxy_->AddNetwork(service_params,
                                                 &network_rpcid)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                            "Failed to add network");
      SetScanState(kScanIdle, scan_method_, __func__);
      return;
    }
    CHECK(!network_rpcid.value().empty());  // No DBus path should be empty.
    service->set_bgscan_string(bgscan_string);
    rpcid_by_service_[service] = network_rpcid;
  } else if (update_supplicant && !new_mac.empty()) {
    // During AddNetwork() (above) MAC is being configured as one of the
    // network parameters, but here we need to send an explicit update.
    std::unique_ptr<SupplicantNetworkProxyInterface> supplicant_network_proxy =
        control_interface()->CreateSupplicantNetworkProxy(network_rpcid);
    KeyValueStore kv;
    kv.Set(WPASupplicant::kNetworkPropertyMACAddrValue, new_mac);
    if (!supplicant_network_proxy->SetProperties(kv)) {
      LOG(ERROR) << "Failed to change MAC for network: "
                 << network_rpcid.value();
      return;
    }
  }

  if (service->HasRecentConnectionIssues()) {
    SetConnectionDebugging(true);
  }

  service->EmitConnectionAttemptEvent();
  supplicant_interface_proxy_->SelectNetwork(network_rpcid);
  SetPendingService(service);
  CHECK(current_service_.get() != pending_service_.get());

  // SelectService here (instead of in LinkEvent, like Ethernet), so
  // that, if we fail to bring up L2, we can attribute failure correctly.
  //
  // TODO(quiche): When we add code for dealing with connection failures,
  // reconsider if this is the right place to change the selected service.
  // see discussion in crbug.com/203282.
  SelectService(service);
  EmitMACAddress(new_mac);
}

void WiFi::DisconnectFromIfActive(WiFiService* service) {
  SLOG(this, 2) << __func__ << " service " << service->log_name();

  if (service != current_service_ && service != pending_service_) {
    if (!service->IsActive(nullptr)) {
      SLOG(this, 2) << "In " << __func__ << "(): " << service->log_name()
                    << " is not active, no need to initiate disconnect";
      return;
    }
  }

  DisconnectFrom(service);
}

void WiFi::DisconnectFrom(WiFiService* service) {
  SLOG(this, 2) << __func__ << " service " << service->log_name();

  if (service != current_service_ && service != pending_service_) {
    // TODO(quiche): Once we have asynchronous reply support, we should
    // generate a D-Bus error here. (crbug.com/206812)
    LOG(WARNING) << "In " << __func__ << "(): "
                 << " ignoring request to disconnect from: "
                 << service->log_name()
                 << " which is neither current nor pending";
    return;
  }

  if (pending_service_ && service != pending_service_) {
    // TODO(quiche): Once we have asynchronous reply support, we should
    // generate a D-Bus error here. (crbug.com/206812)
    LOG(WARNING) << "In " << __func__ << "(): "
                 << " ignoring request to disconnect from: "
                 << service->log_name() << " which is not the pending service.";
    return;
  }

  if (!pending_service_ && service != current_service_) {
    // TODO(quiche): Once we have asynchronous reply support, we should
    // generate a D-Bus error here. (crbug.com/206812)
    LOG(WARNING) << "In " << __func__ << "(): "
                 << " ignoring request to disconnect from: "
                 << service->log_name() << " which is not the current service.";
    return;
  }

  if (pending_service_) {
    // Since wpa_supplicant has not yet set CurrentBSS, we can't depend
    // on this to drive the service state back to idle.  Do that here.
    // Update service state for pending service.
    disconnect_signal_dbm_ = pending_service_->SignalLevel();
    // |expecting_disconnect()| implies that it wasn't a failure to connect.
    // For example we're cancelling pending_service_ before we actually
    // attempted to connect.
    bool is_attempt_failure =
        pending_service_ && !pending_service_->expecting_disconnect();
    ServiceDisconnected(pending_service_, is_attempt_failure);
  } else if (service) {
    disconnect_signal_dbm_ = service->SignalLevel();
  }

  SetPendingService(nullptr);
  StopReconnectTimer();
  StopRequestingStationInfo();

  if (!supplicant_present_) {
    LOG(ERROR) << "In " << __func__ << "(): "
               << "wpa_supplicant is not present; silently resetting "
               << "current_service_.";
    if (current_service_ == selected_service()) {
      DropConnection();
    }
    current_service_ = nullptr;
    return;
  }

  bool disconnect_in_progress = true;
  // We'll call RemoveNetwork and reset |current_service_| after
  // supplicant notifies us that the CurrentBSS has changed.
  if (!supplicant_interface_proxy_->Disconnect()) {
    disconnect_in_progress = false;
  }

  if (supplicant_state_ != WPASupplicant::kInterfaceStateCompleted ||
      !disconnect_in_progress) {
    // Can't depend on getting a notification of CurrentBSS change.
    // So effect changes immediately.  For instance, this can happen when
    // a disconnect is triggered by a BSS going away.
    Error unused_error;
    RemoveNetworkForService(service, &unused_error);
    if (service == selected_service()) {
      DropConnection();
    } else {
      SLOG(this, 5) << __func__ << " skipping DropConnection, "
                    << "selected_service is "
                    << (selected_service() ? selected_service()->log_name()
                                           : "(null)");
    }
    current_service_ = nullptr;
  }

  CHECK(current_service_ == nullptr ||
        current_service_.get() != pending_service_.get());
}

bool WiFi::DisableNetwork(const RpcIdentifier& network) {
  std::unique_ptr<SupplicantNetworkProxyInterface> supplicant_network_proxy =
      control_interface()->CreateSupplicantNetworkProxy(network);
  if (!supplicant_network_proxy->SetEnabled(false)) {
    LOG(ERROR) << "DisableNetwork for " << network.value() << " failed.";
    return false;
  }
  return true;
}

bool WiFi::RemoveNetwork(const RpcIdentifier& network) {
  return supplicant_interface_proxy_->RemoveNetwork(network);
}

bool WiFi::IsIdle() const {
  return !current_service_ && !pending_service_;
}

void WiFi::ClearCachedCredentials(const WiFiService* service) {
  // Give up on the connection attempt for the pending service immediately since
  // the credential for it had already changed. This will allow the Manager to
  // start a new connection attempt for the pending service immediately without
  // waiting for the pending connection timeout.
  // current_service_ will get disconnect notification from the CurrentBSS
  // change event, so no need to explicitly disconnect here.
  if (service == pending_service_) {
    LOG(INFO) << "Disconnect pending service: credential changed";
    DisconnectFrom(pending_service_.get());
  }

  Error unused_error;
  RemoveNetworkForService(service, &unused_error);
}

void WiFi::NotifyEndpointChanged(const WiFiEndpointConstRefPtr& endpoint) {
  provider_->OnEndpointUpdated(endpoint);
}

std::string WiFi::AppendBgscan(WiFiService* service,
                               KeyValueStore* service_params) const {
  std::string method = bgscan_method_;
  int short_interval = bgscan_short_interval_seconds_;
  int signal_threshold = bgscan_signal_threshold_dbm_;
  int scan_interval = kBackgroundScanIntervalSeconds;
  if (method.empty()) {
    // If multiple APs are detected for this SSID, configure the default method
    // with pre-set parameters. Otherwise, use extended scan intervals.
    method = kDefaultBgscanMethod;
    if (service->GetEndpointCount() <= 1) {
      SLOG(nullptr, 3) << "Background scan intervals extended -- single "
                       << "Endpoint for Service.";
      short_interval = kSingleEndpointBgscanShortIntervalSeconds;
      scan_interval = kSingleEndpointBgscanIntervalSeconds;
    }
  } else if (method == WPASupplicant::kNetworkBgscanMethodNone) {
    SLOG(nullptr, 3) << "Background scan disabled -- chose None method.";
  } else {
    // If the background scan method was explicitly specified, honor the
    // configured background scan interval.
    scan_interval = scan_interval_seconds_;
  }
  std::string config_string;
  if (method != WPASupplicant::kNetworkBgscanMethodNone) {
    config_string =
        base::StringPrintf("%s:%d:%d:%d", method.c_str(), short_interval,
                           signal_threshold, scan_interval);
  }
  SLOG(nullptr, 3) << "Background scan: '" << config_string << "'";
  service_params->Set<std::string>(WPASupplicant::kNetworkPropertyBgscan,
                                   config_string);
  return config_string;
}

bool WiFi::ReconfigureBgscan(WiFiService* service) {
  SLOG(this, 3) << __func__ << " for " << service->log_name();
  KeyValueStore bgscan_params;
  std::string bgscan_string = AppendBgscan(service, &bgscan_params);
  if (service->bgscan_string() == bgscan_string) {
    SLOG(this, 3) << "No change in bgscan parameters.";
    return false;
  }

  Error unused_error;
  RpcIdentifier id = FindNetworkRpcidForService(service, &unused_error);
  if (id.value().empty()) {
    return false;
  }

  std::unique_ptr<SupplicantNetworkProxyInterface> network_proxy =
      control_interface()->CreateSupplicantNetworkProxy(id);
  if (!network_proxy->SetProperties(bgscan_params)) {
    LOG(ERROR) << "SetProperties for " << id.value() << " failed.";
    return false;
  }
  LOG(INFO) << "Updated bgscan parameters: " << bgscan_string;
  service->set_bgscan_string(bgscan_string);
  return true;
}

bool WiFi::ReconfigureBgscanForRelevantServices() {
  bool ret = true;
  if (current_service_) {
    ret = ReconfigureBgscan(current_service_.get()) && ret;
  }
  if (pending_service_) {
    ret = ReconfigureBgscan(pending_service_.get()) && ret;
  }
  return ret;
}

std::string WiFi::GetBgscanMethod(Error* /* error */) {
  return bgscan_method_.empty() ? kDefaultBgscanMethod : bgscan_method_;
}

bool WiFi::SetBgscanMethod(const std::string& method, Error* error) {
  if (method != WPASupplicant::kNetworkBgscanMethodSimple &&
      method != WPASupplicant::kNetworkBgscanMethodLearn &&
      method != WPASupplicant::kNetworkBgscanMethodNone) {
    const auto error_message =
        base::StringPrintf("Unrecognized bgscan method %s", method.c_str());
    LOG(WARNING) << error_message;
    error->Populate(Error::kInvalidArguments, error_message);
    return false;
  }
  if (bgscan_method_ == method) {
    return false;
  }
  bgscan_method_ = method;
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::SetBgscanShortInterval(const uint16_t& seconds, Error* /*error*/) {
  if (bgscan_short_interval_seconds_ == seconds) {
    return false;
  }
  bgscan_short_interval_seconds_ = seconds;
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::SetBgscanSignalThreshold(const int32_t& dbm, Error* /*error*/) {
  if (bgscan_signal_threshold_dbm_ == dbm) {
    return false;
  }
  bgscan_signal_threshold_dbm_ = dbm;
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::SetScanInterval(const uint16_t& seconds, Error* /*error*/) {
  if (scan_interval_seconds_ == seconds) {
    return false;
  }
  scan_interval_seconds_ = seconds;
  if (enabled()) {
    StartScanTimer();
  }
  // The scan interval affects both foreground scans (handled by
  // |scan_timer_callback_|), and background scans (handled by
  // supplicant).
  return ReconfigureBgscanForRelevantServices();
}

bool WiFi::GetRandomMacEnabled(Error* /*error*/) {
  return random_mac_enabled_;
}

bool WiFi::SetRandomMacEnabled(const bool& enabled, Error* error) {
  if (!supplicant_present_ || !supplicant_interface_proxy_.get()) {
    SLOG(this, 2) << "Ignoring random MAC while supplicant is not present.";
    return false;
  }

  if (random_mac_enabled_ == enabled) {
    return false;
  }
  if (!random_mac_supported_) {
    const std::string message =
        "This WiFi device does not support MAC address randomization";
    LOG(ERROR) << message;
    if (error) {
      error->Populate(Error::kNotSupported, message, FROM_HERE);
    }
    return false;
  }
  if ((enabled && supplicant_interface_proxy_->EnableMacAddressRandomization(
                      kRandomMacMask, sched_scan_supported_)) ||
      (!enabled &&
       supplicant_interface_proxy_->DisableMacAddressRandomization())) {
    random_mac_enabled_ = enabled;
    return true;
  }
  return false;
}

void WiFi::ClearBgscanMethod(Error* /*error*/) {
  bgscan_method_.clear();
}

bool WiFi::SetInterworkingSelectEnabled(const bool& enabled,
                                        Error* /* error */) {
  if (interworking_select_enabled_ == enabled) {
    // No-op
    return false;
  }
  interworking_select_enabled_ = enabled;
  if (interworking_select_enabled_) {
    // Interworking selection has just been enabled, we want to try a selection
    // after next scan.
    need_interworking_select_ = true;
  }
  return true;
}

void WiFi::AssocStatusChanged(const int32_t new_assoc_status) {
  SLOG(this, 3) << "WiFi " << link_name()
                << " supplicant updated AssocStatusCode to " << new_assoc_status
                << " (was " << supplicant_assoc_status_ << ")";
  if (supplicant_auth_status_ != IEEE_80211::kStatusCodeSuccessful) {
    LOG(WARNING) << "Supplicant authentication status is set to "
                 << supplicant_auth_status_
                 << " despite getting a new association status.";
    supplicant_auth_status_ = IEEE_80211::kStatusCodeSuccessful;
  }
  supplicant_assoc_status_ = new_assoc_status;
}

void WiFi::AuthStatusChanged(const int32_t new_auth_status) {
  SLOG(this, 3) << "WiFi " << link_name()
                << " supplicant updated AuthStatusCode to " << new_auth_status
                << " (was " << supplicant_auth_status_ << ")";
  if (supplicant_assoc_status_ != IEEE_80211::kStatusCodeSuccessful) {
    LOG(WARNING) << "Supplicant association status is set to "
                 << supplicant_assoc_status_
                 << " despite getting a new authentication status.";
    supplicant_assoc_status_ = IEEE_80211::kStatusCodeSuccessful;
  }
  supplicant_auth_status_ = new_auth_status;
}

void WiFi::CurrentBSSChanged(const RpcIdentifier& new_bss) {
  LOG(INFO) << "WiFi " << link_name() << " CurrentBSS "
            << supplicant_bss_.value() << " -> " << new_bss.value();

  // Store signal strength of BSS when disconnecting.
  if (supplicant_bss_.value() != WPASupplicant::kCurrentBSSNull &&
      new_bss.value() == WPASupplicant::kCurrentBSSNull) {
    const WiFiEndpointConstRefPtr endpoint(GetCurrentEndpoint());
    if (endpoint == nullptr) {
      LOG(ERROR) << "Can't get endpoint for current supplicant BSS "
                 << supplicant_bss_.value();
      // Default to value that will not imply out of range error in
      // ServiceDisconnected or PendingTimeoutHandler.
      disconnect_signal_dbm_ = kDefaultDisconnectDbm;
    } else {
      disconnect_signal_dbm_ = endpoint->signal_strength();
      LOG(INFO) << "Current BSS signal strength at disconnect: "
                << disconnect_signal_dbm_;
    }
  }

  supplicant_bss_ = new_bss;
  has_already_completed_ = false;
  is_roaming_in_progress_ = false;
  if (current_service_) {
    current_service_->SetIsRekeyInProgress(false);
  }

  // Any change in CurrentBSS means supplicant is actively changing our
  // connectivity.  We no longer need to track any previously pending
  // reconnect.
  StopReconnectTimer();
  StopRequestingStationInfo();

  if (new_bss.value() == WPASupplicant::kCurrentBSSNull) {
    HandleDisconnect();
    if (!provider_->GetHiddenSSIDList().empty()) {
      // Before disconnecting, wpa_supplicant probably scanned for
      // APs. So, in the normal case, we defer to the timer for the next scan.
      //
      // However, in the case of hidden SSIDs, supplicant knows about
      // at most one of them. (That would be the hidden SSID we were
      // connected to, if applicable.)
      //
      // So, in this case, we initiate an immediate scan. This scan
      // will include the hidden SSIDs we know about (up to the limit of
      // kScanMAxSSIDsPerScan).
      //
      // We may want to reconsider this immediate scan, if/when shill
      // takes greater responsibility for scanning (vs. letting
      // supplicant handle most of it).
      Scan(nullptr, __func__);
    }
  } else {
    HandleRoam(new_bss);
  }

  // Reset the EAP handler only after calling HandleDisconnect() above
  // so our EAP state could be used to detect a failed authentication.
  eap_state_handler_->Reset();
  pending_eap_failure_ = Service::kFailureNone;

  // If we are selecting a new service, or if we're clearing selection
  // of a something other than the pending service, call SelectService.
  // Otherwise skip SelectService, since this will cause the pending
  // service to be marked as Idle.
  if (current_service_ || selected_service() != pending_service_) {
    SelectService(current_service_);
  }

  // Invariant check: a Service can either be current, or pending, but
  // not both.
  CHECK(current_service_.get() != pending_service_.get() ||
        current_service_.get() == nullptr);

  // If we are no longer debugging a problematic WiFi connection, return
  // to the debugging level indicated by the WiFi debugging scope.
  if ((!current_service_ || !current_service_->HasRecentConnectionIssues()) &&
      (!pending_service_ || !pending_service_->HasRecentConnectionIssues())) {
    SetConnectionDebugging(false);
  }
}

void WiFi::DisconnectReasonChanged(const int32_t new_value) {
  int32_t sanitized_value =
      (new_value == INT32_MIN) ? INT32_MAX : abs(new_value);
  if (sanitized_value > IEEE_80211::kReasonCodeMax) {
    LOG(WARNING) << "Received disconnect reason " << sanitized_value
                 << " from supplicant greater than kReasonCodeMax."
                 << " Perhaps WiFiReasonCode needs to be updated.";
    sanitized_value = IEEE_80211::kReasonCodeMax;
  }
  auto new_reason = static_cast<IEEE_80211::WiFiReasonCode>(sanitized_value);

  std::string update;
  if (supplicant_disconnect_reason_ != IEEE_80211::kReasonCodeInvalid) {
    update = base::StringPrintf(" from %d", supplicant_disconnect_reason_);
  }

  std::string new_disconnect_description = "Success";
  if (new_reason != 0) {
    new_disconnect_description = IEEE_80211::ReasonToString(new_reason);
  }

  LOG(INFO) << base::StringPrintf(
      "WiFi %s supplicant updated DisconnectReason%s to %d (%s)",
      link_name().c_str(), update.c_str(), new_reason,
      new_disconnect_description.c_str());
  supplicant_disconnect_reason_ = new_reason;

  Metrics::WiFiDisconnectByWhom by_whom = (new_value < 0)
                                              ? Metrics::kDisconnectedNotByAp
                                              : Metrics::kDisconnectedByAp;
  metrics()->Notify80211Disconnect(by_whom, new_reason);
}

void WiFi::CurrentAuthModeChanged(const std::string& auth_mode) {
  if (auth_mode != WPASupplicant::kAuthModeInactive &&
      auth_mode != WPASupplicant::kAuthModeUnknown) {
    supplicant_auth_mode_ = auth_mode;
  }
}

bool WiFi::IsStateTransitionConnectionMaintenance(
    const WiFiService& service) const {
  // In some cases we see changes in wpa_supplicant's state that are caused by
  // a "maintenance" event that does not really necessarily reflect a change
  // in the high-level user-visible "connected" state. For example, rekeying
  // will trigger a transition from |kInterfaceStateCompleted| to
  // |kInterfaceStateGroupHandshake| and back to |kInterfaceStateCompleted|,
  // but it's not a full connection attempt.
  return service.is_rekey_in_progress() || is_roaming_in_progress_;
}

void WiFi::HandleDisconnect() {
  // Identify the affected service. We expect to get a disconnect
  // event when we fall off a Service that we were connected
  // to. However, we also allow for the case where we get a disconnect
  // event while attempting to connect from a disconnected state.
  WiFiService* affected_service =
      current_service_.get() ? current_service_.get() : pending_service_.get();

  if (!affected_service) {
    SLOG(this, 2) << "WiFi " << link_name()
                  << " disconnected while not connected or connecting";
    return;
  }

  SLOG(this, 2) << "WiFi " << link_name() << " disconnected from "
                << " (or failed to connect to) "
                << affected_service->log_name();

  if (affected_service == current_service_.get() && pending_service_.get()) {
    // Current service disconnected intentionally for network switching,
    // set service state to idle.
    affected_service->SetState(Service::kStateIdle);
  } else {
    // Make the difference between a failure to connect to a service and a
    // disconnection from a service we were connected to. Checking for
    // |pending_service_| is not necessarily sufficient, since it could be the
    // case that we were connected and were disconnected intentionally to
    // attempt to connect to another service, which would be pending.
    bool is_attempt_failure =
        pending_service_ && (affected_service != current_service_.get());
    // In some cases (for example when the 4-way handshake is still ongoing),
    // |pending_service_| has already been reset to |nullptr| since we had
    // already gone through Auth+Assoc stages. It is still a failure to
    // attempt to connect when we fail then, for example during the handshake.
    // Because of that we also have to check the state of wpa_supplicant to see
    // if it was in the middle of e.g. the 4-way handshake when it reported a
    // failure. However, to ensure that we don't incorrectly classify
    // "maintenance" operations (e.g. rekeying) as connection *attempt* failures
    // rather than disconnections, we also need to verify that we're not
    // currently performing a "maintenance" operation that would temporarily
    // move the state back from "connected" to "handshake" (rekeying case) or
    // "associating" (roaming case) or similar.
    // If all those conditions (state is compatible with in-progress connection
    // and there is no ongoing "maintenance" operation) then a failure implies
    // a failed *attempted* connection rather than a disconnection.
    if (!is_attempt_failure) {
      is_attempt_failure =
          IsWPAStateConnectionInProgress(supplicant_state_) &&
          !IsStateTransitionConnectionMaintenance(*affected_service);
    }
    // Perform necessary handling for disconnected service.
    ServiceDisconnected(affected_service, is_attempt_failure);
  }

  current_service_ = nullptr;

  if (affected_service == selected_service()) {
    // If our selected service has disconnected, destroy IP configuration state.
    DropConnection();
  }

  Error error;
  if (!DisableNetworkForService(affected_service, &error)) {
    if (error.type() == Error::kNotFound) {
      SLOG(this, 2) << "WiFi " << link_name() << " disconnected from "
                    << " (or failed to connect to) service "
                    << affected_service->log_name() << ", "
                    << "but could not find supplicant network to disable.";
    } else {
      LOG(ERROR) << "DisableNetwork failed on " << link_name()
                 << "for: " << affected_service->log_name() << ".";
    }
  }

  metrics()->NotifySignalAtDisconnect(*affected_service,
                                      disconnect_signal_dbm_);
  affected_service->NotifyCurrentEndpoint(nullptr);
  metrics()->NotifyServiceDisconnect(*affected_service);

  if (affected_service == pending_service_.get()) {
    // The attempt to connect to |pending_service_| failed. Clear
    // |pending_service_|, to indicate we're no longer in the middle
    // of a connect request.
    SetPendingService(nullptr);
  } else if (pending_service_) {
    // We've attributed the disconnection to what was the
    // |current_service_|, rather than the |pending_service_|.
    //
    // If we're wrong about that (i.e. supplicant reported this
    // CurrentBSS change after attempting to connect to
    // |pending_service_|), we're depending on supplicant to retry
    // connecting to |pending_service_|, and delivering another
    // CurrentBSS change signal in the future.
    //
    // Log this fact, to help us debug (in case our assumptions are
    // wrong).
    SLOG(this, 2) << "WiFi " << link_name()
                  << " pending connection to: " << pending_service_->log_name()
                  << " after disconnect";
  }

  // If we disconnect, initially scan at a faster frequency, to make sure
  // we've found all available APs.
  RestartFastScanAttempts();
}

void WiFi::ServiceDisconnected(WiFiServiceRefPtr affected_service,
                               bool is_attempt_failure) {
  SLOG(this, 1) << __func__ << " service " << affected_service->log_name();

  // Check if service was explicitly disconnected due to failure or
  // is explicitly disconnected by user.
  if (!affected_service->IsInFailState() &&
      !affected_service->explicitly_disconnected() &&
      !affected_service->expecting_disconnect()) {
    // Check auth/assoc status codes and send metric if a status code indicates
    // failure (otherwise logs and UMA will only contain status code failures
    // caused by a pending connection timeout).
    Service::ConnectFailure failure_from_status = ExamineStatusCodes();

    // Determine disconnect failure reason.
    Service::ConnectFailure failure;
    if (SuspectCredentials(affected_service, &failure)) {
      // If we've reached here, |SuspectCredentials| has already set
      // |failure| to the appropriate value.
    } else {
      SLOG(this, 2) << "Supplicant disconnect reason: "
                    << IEEE_80211::ReasonToString(
                           supplicant_disconnect_reason_);
      // Disconnected for some other reason.
      // Map IEEE error codes to shill error codes.
      switch (supplicant_disconnect_reason_) {
        case IEEE_80211::kReasonCodeInactivity:
        case IEEE_80211::kReasonCodeSenderHasLeft:
          SLOG(this, 2) << "Disconnect signal: " << disconnect_signal_dbm_;
          if (SignalOutOfRange(disconnect_signal_dbm_)) {
            failure = Service::kFailureOutOfRange;
          } else {
            failure = Service::kFailureDisconnect;
          }
          break;
        case IEEE_80211::kReasonCodeNonAuthenticated:
        case IEEE_80211::kReasonCodeReassociationNotAuthenticated:
        case IEEE_80211::kReasonCodePreviousAuthenticationInvalid:
          failure = Service::kFailureNotAuthenticated;
          break;
        case IEEE_80211::kReasonCodeNonAssociated:
          failure = Service::kFailureNotAssociated;
          break;
        case IEEE_80211::kReasonCodeTooManySTAs:
          failure = Service::kFailureTooManySTAs;
          break;
        case IEEE_80211::kReasonCode8021XAuth:
          failure = Service::kFailureEAPAuthentication;
          break;
        default:
          // If we don't have a failure type to set given the disconnect reason,
          // see if assoc/auth status codes can lead to an informative failure
          // reason. Will be kFailureUnknown if that isn't the case.
          failure = failure_from_status;
          break;
      }
    }
    if (failure == Service::kFailureEAPAuthentication &&
        pending_eap_failure_ != Service::kFailureNone) {
      failure = pending_eap_failure_;
    } else if (failure == Service::kFailureUnknown &&
               SignalOutOfRange(disconnect_signal_dbm_)) {
      // We have assumed we have disconnected since the current endpoint no
      // longer shows up in the scan. If wpa_supplicant did not give us a
      // reason code, then it will be |kFailureUnknown|. A check here can
      // verify the difference between a true unknown failure and an out of
      // range failure.
      failure = Service::kFailureOutOfRange;
    }
    if (!affected_service->ShouldIgnoreFailure()) {
      affected_service->SetFailure(failure);
    }
    if (is_attempt_failure) {
      // We attempted to connect to a service but the attempt failed. Report
      // a failure to connect (as opposed to a disconnection from a service we
      // were successfully connected to).
      metrics()->NotifyWiFiConnectionAttemptResult(
          Metrics::ConnectFailureToServiceErrorEnum(failure));
      LOG(ERROR) << "Failed to connect due to reason: "
                 << Service::ConnectFailureToString(failure);
    } else {
      LOG(ERROR) << "Disconnected due to reason: "
                 << Service::ConnectFailureToString(failure);
    }
  }

  // Set service state back to idle, so this service can be used for
  // future connections.
  affected_service->SetState(Service::kStateIdle);
}

bool WiFi::SignalOutOfRange(const int16_t& disconnect_signal) {
  return disconnect_signal <= disconnect_threshold_dbm_ &&
         disconnect_signal != kDefaultDisconnectDbm;
}

Service::ConnectFailure WiFi::ExamineStatusCodes() const {
  bool is_auth_error =
      supplicant_auth_status_ != IEEE_80211::kStatusCodeSuccessful;
  bool is_assoc_error =
      supplicant_assoc_status_ != IEEE_80211::kStatusCodeSuccessful;
  DCHECK(!(is_auth_error && is_assoc_error));
  if (!is_auth_error && !is_assoc_error) {
    return Service::kFailureUnknown;
  }

  int32_t status = supplicant_auth_status_;
  std::string error_name = "Authentication";
  std::string metric_name = Metrics::kMetricWiFiAuthFailureType;
  Service::ConnectFailure proposed_failure = Service::kFailureNotAuthenticated;
  if (is_assoc_error) {
    status = supplicant_assoc_status_;
    error_name = "Association";
    metric_name = Metrics::kMetricWiFiAssocFailureType;
    proposed_failure = Service::kFailureNotAssociated;
  }

  LOG(INFO) << "WiFi Device " << link_name() << ": " << error_name << " error "
            << status << " ("
            << IEEE_80211::StatusToString(
                   static_cast<IEEE_80211::WiFiStatusCode>(status))
            << ")";
  metrics()->SendEnumToUMA(metric_name, status, IEEE_80211::kStatusCodeMax);

  if (status == IEEE_80211::kStatusCodeMaxSta) {
    proposed_failure = Service::kFailureTooManySTAs;
  }
  return proposed_failure;
}

// We use the term "Roam" loosely. In particular, we include the case
// where we "Roam" to a BSS from the disconnected state.
void WiFi::HandleRoam(const RpcIdentifier& new_bss) {
  EndpointMap::iterator endpoint_it = endpoint_by_rpcid_.find(new_bss);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    LOG(WARNING) << "WiFi " << link_name() << " connected to unknown BSS "
                 << new_bss.value();
    return;
  }

  const WiFiEndpointConstRefPtr endpoint(endpoint_it->second);
  WiFiServiceRefPtr service = provider_->FindServiceForEndpoint(endpoint);
  if (!service) {
    LOG(WARNING) << "WiFi " << link_name()
                 << " could not find Service for Endpoint "
                 << endpoint->bssid_string() << " (service will be unchanged)";
    return;
  }

  metrics()->NotifyAp80211kSupport(
      endpoint->krv_support().neighbor_list_supported);
  metrics()->NotifyAp80211rSupport(endpoint->krv_support().ota_ft_supported,
                                   endpoint->krv_support().otds_ft_supported);
  metrics()->NotifyAp80211vDMSSupport(endpoint->krv_support().dms_supported);
  metrics()->NotifyAp80211vBSSMaxIdlePeriodSupport(
      endpoint->krv_support().bss_max_idle_period_supported);
  metrics()->NotifyAp80211vBSSTransitionSupport(
      endpoint->krv_support().bss_transition_supported);
  metrics()->NotifyHS20Support(endpoint->hs20_information().supported,
                               endpoint->hs20_information().version);
  metrics()->NotifyMBOSupport(endpoint->mbo_support());

  SLOG(this, 2) << "WiFi " << link_name() << " roamed to Endpoint "
                << endpoint->bssid_string() << " "
                << LogSSID(endpoint->ssid_string());

  service->NotifyCurrentEndpoint(endpoint);

  if (pending_service_.get() && service.get() != pending_service_.get()) {
    // The Service we've roamed on to is not the one we asked for.
    // We assume that this is transient, and that wpa_supplicant
    // is trying / will try to connect to |pending_service_|.
    //
    // If it succeeds, we'll end up back here, but with |service|
    // pointing at the same service as |pending_service_|.
    //
    // If it fails, we'll process things in HandleDisconnect.
    //
    // So we leave |pending_service_| untouched.
    SLOG(this, 2) << "WiFi " << link_name() << " new current Endpoint "
                  << endpoint->bssid_string()
                  << " is not part of pending service "
                  << pending_service_->log_name();

    // Quick check: if we didn't roam onto |pending_service_|, we
    // should still be on |current_service_|.
    if (service.get() != current_service_.get()) {
      LOG(WARNING) << "WiFi " << link_name() << " new current Endpoint "
                   << endpoint->bssid_string()
                   << " is neither part of pending service "
                   << pending_service_->log_name()
                   << " nor part of current service "
                   << (current_service_ ? current_service_->log_name()
                                        : "(nullptr)");
      // wpa_supplicant has no knowledge of the pending_service_ at this point.
      // Disconnect the pending_service_, so that it can be connectable again.
      // Otherwise, we'd have to wait for the pending timeout to trigger the
      // disconnect. This will speed up the connection attempt process for
      // the pending_service_.
      DisconnectFrom(pending_service_.get());
    }
    return;
  }

  if (pending_service_) {
    // We assume service.get() == pending_service_.get() here, because
    // of the return in the previous if clause.
    //
    // Boring case: we've connected to the service we asked
    // for. Simply update |current_service_| and |pending_service_|.
    current_service_ = service;
    SetScanState(kScanConnected, scan_method_, __func__);
    SetPendingService(nullptr);
    return;
  }

  // |pending_service_| was nullptr, so we weren't attempting to connect
  // to a new Service. Quick check that we're still on |current_service_|.
  if (service.get() != current_service_.get()) {
    LOG(WARNING) << "WiFi " << link_name() << " new current Endpoint "
                 << endpoint->bssid_string()
                 << (current_service_.get()
                         ? base::StringPrintf(
                               " is not part of current service %s",
                               current_service_->log_name().c_str())
                         : " with no current service");
    // We didn't expect to be here, but let's cope as well as we
    // can. Update |current_service_| to keep it in sync with
    // supplicant.
    current_service_ = service;

    // If this service isn't already marked as actively connecting (likely,
    // since this service is a bit of a surprise) set the service as
    // associating.
    if (!current_service_->IsConnecting()) {
      current_service_->SetState(Service::kStateAssociating);
    }

    return;
  }

  // At this point, we know that |pending_service_| was nullptr, and that
  // we're still on |current_service_|.  We should track this roaming
  // event so we can refresh our IPConfig if it succeeds.
  is_roaming_in_progress_ = true;

  return;
}

RpcIdentifier WiFi::FindNetworkRpcidForService(const WiFiService* service,
                                               Error* error) {
  ReverseServiceMap::const_iterator rpcid_it = rpcid_by_service_.find(service);
  if (rpcid_it == rpcid_by_service_.end()) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot find supplicant network rpcid for service %s",
        link_name().c_str(), service->log_name().c_str());
    // There are contexts where this is not an error, such as when a service
    // is clearing whatever cached credentials may not exist.
    SLOG(this, 2) << error_message;
    if (error) {
      error->Populate(Error::kNotFound, error_message);
    }
    return RpcIdentifier("");
  }

  return rpcid_it->second;
}

bool WiFi::DisableNetworkForService(const WiFiService* service, Error* error) {
  RpcIdentifier rpcid = FindNetworkRpcidForService(service, error);
  if (rpcid.value().empty()) {
    // Error is already populated.
    return false;
  }

  if (!DisableNetwork(rpcid)) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot disable network for service %s: "
        "DBus operation failed for rpcid %s.",
        link_name().c_str(), service->log_name().c_str(),
        rpcid.value().c_str());
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          error_message);

    // Make sure that such errored networks are removed, so problems do not
    // propagate to future connection attempts.
    RemoveNetwork(rpcid);
    rpcid_by_service_.erase(service);

    return false;
  }

  return true;
}

bool WiFi::RemoveNetworkForService(const WiFiService* service, Error* error) {
  RpcIdentifier rpcid = FindNetworkRpcidForService(service, error);
  if (rpcid.value().empty()) {
    // Error is already populated.
    return false;
  }

  // Erase the rpcid from our tables regardless of failure below, since even
  // if in failure, we never want to use this network again.
  rpcid_by_service_.erase(service);

  // TODO(quiche): Reconsider giving up immediately. Maybe give
  // wpa_supplicant some time to retry, first.
  if (!RemoveNetwork(rpcid)) {
    const auto error_message = base::StringPrintf(
        "WiFi %s cannot remove network for service %s: "
        "DBus operation failed for rpcid %s.",
        link_name().c_str(), service->log_name().c_str(),
        rpcid.value().c_str());
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          error_message);
    return false;
  }

  return true;
}

void WiFi::PendingScanResultsHandler() {
  CHECK(pending_scan_results_);
  SLOG(this, 2) << __func__ << " with " << pending_scan_results_->results.size()
                << " results and is_complete set to "
                << pending_scan_results_->is_complete;
  for (const auto& result : pending_scan_results_->results) {
    if (result.is_removal) {
      BSSRemovedTask(result.path);
    } else {
      BSSAddedTask(result.path, result.properties);
    }
  }
  if (pending_scan_results_->is_complete) {
    ScanDoneTask();
  }
  pending_scan_results_.reset();
}

bool WiFi::ParseWiphyIndex(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command: " << nl80211_message.command();
    return false;
  }
  if (!nl80211_message.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_WIPHY, &wiphy_index_)) {
    LOG(ERROR) << "NL80211_CMD_NEW_WIPHY had no NL80211_ATTR_WIPHY";
    return false;
  }
  return true;
}

void WiFi::ParseFeatureFlags(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command: " << nl80211_message.command();
    return;
  }

  // Look for scheduled scan support.
  AttributeListConstRefPtr cmds;
  if (nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SUPPORTED_COMMANDS, &cmds)) {
    AttributeIdIterator cmds_iter(*cmds);
    for (; !cmds_iter.AtEnd(); cmds_iter.Advance()) {
      uint32_t cmd;
      if (!cmds->GetU32AttributeValue(cmds_iter.GetId(), &cmd)) {
        LOG(ERROR) << "Failed to get supported cmd " << cmds_iter.GetId();
        return;
      }
      if (cmd == NL80211_CMD_START_SCHED_SCAN)
        sched_scan_supported_ = true;
    }
  }

  uint32_t flag;
  if (nl80211_message.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_FEATURE_FLAGS, &flag)) {
    // There are two flags for MAC randomization: one for regular scans and one
    // for scheduled scans. Only look for the latter if scheduled scans are
    // supported.
    //
    // This flag being set properly currently relies on the assumption that
    // sched_scan_supported_ is set sometime before this codepath is called.
    // A potential TODO to not rely on this assumption is to accumulate all
    // split messages, log the DONE reply, and perform our determinations at the
    // end (aka set this flag). More discussion can be found on
    // crrev.com/c/3028791.

    random_mac_supported_ =
        (flag & NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR) &&
        (!sched_scan_supported_ ||
         (flag & NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR));
    if (random_mac_supported_) {
      SLOG(this, 7) << __func__ << ": "
                    << "Supports random MAC: " << random_mac_supported_;
    }
  }
}

void WiFi::HandleNetlinkBroadcast(const NetlinkMessage& netlink_message) {
  // We only handle nl80211 commands.
  if (netlink_message.message_type() != Nl80211Message::GetMessageType()) {
    SLOG(this, 7) << __func__ << ": "
                  << "Not a NL80211 Message";
    return;
  }
  const Nl80211Message& nl80211_msg =
      *reinterpret_cast<const Nl80211Message*>(&netlink_message);

  // Pass nl80211 message to appropriate handler function.
  if (nl80211_msg.command() == TriggerScanMessage::kCommand) {
    OnScanStarted(nl80211_msg);
  } else if (nl80211_msg.command() == WiphyRegChangeMessage::kCommand ||
             nl80211_msg.command() == RegChangeMessage::kCommand) {
    OnRegChange(nl80211_msg);
  } else if (nl80211_msg.command() == NotifyCqmMessage::kCommand) {
    if (wifi_cqm_) {
      wifi_cqm_->OnCQMNotify(nl80211_msg);
    }
  }
}

void WiFi::OnScanStarted(const Nl80211Message& scan_trigger_msg) {
  if (scan_trigger_msg.command() != TriggerScanMessage::kCommand) {
    SLOG(this, 7) << __func__ << ": "
                  << "Not a NL80211_CMD_TRIGGER_SCAN message";
    return;
  }
  uint32_t wiphy_index;
  if (!scan_trigger_msg.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_WIPHY, &wiphy_index)) {
    LOG(ERROR) << "NL80211_CMD_TRIGGER_SCAN had no NL80211_ATTR_WIPHY";
    return;
  }
  if (wiphy_index != wiphy_index_) {
    SLOG(this, 7) << __func__ << ": "
                  << "Scan trigger not meant for this interface";
    return;
  }
  bool is_active_scan = false;
  AttributeListConstRefPtr ssids;
  if (scan_trigger_msg.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SCAN_SSIDS, &ssids)) {
    AttributeIdIterator ssid_iter(*ssids);
    // If any SSIDs (even the empty wild card) are reported, an active scan was
    // launched. Otherwise, a passive scan was launched.
    is_active_scan = !ssid_iter.AtEnd();
  }
  if (wake_on_wifi_) {
    wake_on_wifi_->OnScanStarted(is_active_scan);
  }
}

void WiFi::OnGetReg(const Nl80211Message& nl80211_message) {
  if (nl80211_message.command() != GetRegMessage::kCommand) {
    LOG(ERROR) << __func__
               << ": unexpected command: " << nl80211_message.command_string();
    return;
  }

  // Extract country code.
  std::string country_code;
  if (!nl80211_message.const_attributes()->GetStringAttributeValue(
          NL80211_ATTR_REG_ALPHA2, &country_code)) {
    SLOG(this, 3) << "Regulatory message had no NL80211_ATTR_REG_ALPHA2";
    return;  // If no alpha2 value present, ignore it.
  }
  HandleCountryChange(country_code);

  uint8_t region;
  if (!nl80211_message.const_attributes()->GetU8AttributeValue(
          NL80211_ATTR_DFS_REGION, &region)) {
    SLOG(this, 1) << "Regulatory message has no DFS region, using: "
                  << NL80211_DFS_UNSET;
    region = NL80211_DFS_UNSET;
  } else {
    SLOG(this, 1) << "DFS region: " << region;
  }

  manager()->power_manager()->ChangeRegDomain(
      static_cast<nl80211_dfs_regions>(region));
}

void WiFi::OnRegChange(const Nl80211Message& nl80211_message) {
  if (nl80211_message.command() != WiphyRegChangeMessage::kCommand &&
      nl80211_message.command() != RegChangeMessage::kCommand) {
    LOG(ERROR) << __func__
               << ": unexpected command: " << nl80211_message.command_string();
    return;
  }

  // Ignore regulatory domain CHANGE events initiated by user.
  uint32_t initiator;
  if (!nl80211_message.const_attributes()->GetU32AttributeValue(
          NL80211_ATTR_REG_INITIATOR, &initiator)) {
    SLOG(this, 3) << "No NL80211_ATTR_REG_INITIATOR in command "
                  << nl80211_message.command_string();
    return;
  }
  if (initiator == NL80211_REGDOM_SET_BY_USER) {
    SLOG(this, 3) << "Ignoring regulatory domain change initiated by user.";
    return;
  }

  // CHANGE events don't have all the useful attributes (e.g.,
  // NL80211_ATTR_DFS_REGION); request the full info now.
  GetRegulatory();
}

void WiFi::HandleCountryChange(std::string country_code) {
  // Variable to keep track of current regulatory domain to reduce noise in
  // reported "change" events.
  static int current_reg_dom_val = -1;

  // Get Regulatory Domain value from received country code.
  int reg_dom_val = Metrics::GetRegulatoryDomainValue(country_code);
  if (reg_dom_val == Metrics::RegulatoryDomain::kCountryCodeInvalid) {
    LOG(WARNING) << "Unsupported NL80211_ATTR_REG_ALPHA2 attribute: "
                 << country_code;
  } else {
    SLOG(this, 3) << base::StringPrintf(
        "Regulatory domain change message received with alpha2 %s (metric val: "
        "%d)",
        country_code.c_str(), reg_dom_val);
  }

  // Only send to UMA when regulatory domain changes to reduce noise in metrics.
  if (reg_dom_val != current_reg_dom_val) {
    current_reg_dom_val = reg_dom_val;
    metrics()->SendEnumToUMA(Metrics::kMetricRegulatoryDomain, reg_dom_val,
                             Metrics::RegulatoryDomain::kRegDomMaxValue);
  }
}

void WiFi::BSSAddedTask(const RpcIdentifier& path,
                        const KeyValueStore& properties) {
  // Note: we assume that BSSIDs are unique across endpoints. This
  // means that if an AP reuses the same BSSID for multiple SSIDs, we
  // lose.
  WiFiEndpointRefPtr endpoint(
      new WiFiEndpoint(control_interface(), this, path, properties, metrics()));
  SLOG(this, 5) << "Found endpoint. "
                << "RPC path: " << path.value() << ", "
                << LogSSID(endpoint->ssid_string()) << ", "
                << "bssid: " << endpoint->bssid_string() << ", "
                << "signal: " << endpoint->signal_strength() << ", "
                << "security: " << endpoint->security_mode() << ", "
                << "frequency: " << endpoint->frequency();

  if (endpoint->ssid_string().empty()) {
    // Don't bother trying to find or create a Service for an Endpoint
    // without an SSID. We wouldn't be able to connect to it anyway.
    return;
  }

  if (endpoint->ssid()[0] == 0) {
    // Assume that an SSID starting with nullptr is bogus/misconfigured,
    // and filter it out.
    return;
  }

  if (endpoint->network_mode().empty()) {
    // Unsupported modes (e.g., ad-hoc) should be ignored.
    return;
  }

  bool service_has_matched = provider_->OnEndpointAdded(endpoint);
  // Adding a single endpoint can change the bgscan parameters for no more than
  // one active Service. Try pending_service_ only if current_service_ doesn't
  // change.
  if ((!current_service_ || !ReconfigureBgscan(current_service_.get())) &&
      pending_service_) {
    ReconfigureBgscan(pending_service_.get());
  }

  // Do this last, to maintain the invariant that any Endpoint we
  // know about has a corresponding Service.
  //
  // TODO(quiche): Write test to verify correct behavior in the case
  // where we get multiple BSSAdded events for a single endpoint.
  // (Old Endpoint's refcount should fall to zero, and old Endpoint
  // should be destroyed.)
  endpoint_by_rpcid_[path] = endpoint;
  endpoint->Start();

  // Keep track of Passpoint compatible endpoints to trigger an interworking
  // selection later if needed.
  if (endpoint->hs20_information().supported) {
    hs20_bss_count_++;
  }
  need_interworking_select_ =
      need_interworking_select_ ||
      (!service_has_matched && endpoint->hs20_information().supported);
}

void WiFi::BSSRemovedTask(const RpcIdentifier& path) {
  EndpointMap::iterator i = endpoint_by_rpcid_.find(path);
  if (i == endpoint_by_rpcid_.end()) {
    SLOG(this, 1) << "WiFi " << link_name() << " could not find BSS "
                  << path.value() << " to remove.";
    return;
  }

  WiFiEndpointRefPtr endpoint = i->second;
  CHECK(endpoint);
  endpoint_by_rpcid_.erase(i);

  if (endpoint->hs20_information().supported) {
    CHECK_NE(hs20_bss_count_, 0u);
    hs20_bss_count_--;
  }

  WiFiServiceRefPtr service = provider_->OnEndpointRemoved(endpoint);
  if (!service) {
    // Removing a single endpoint can change the bgscan parameters for no more
    // than one active Service. Try pending_service_ only if current_service_
    // doesn't change.
    if ((!current_service_ || !ReconfigureBgscan(current_service_.get())) &&
        pending_service_) {
      ReconfigureBgscan(pending_service_.get());
    }
    return;
  }
  Error unused_error;
  RemoveNetworkForService(service.get(), &unused_error);

  bool disconnect_service = !service->HasEndpoints() &&
                            (service->IsConnecting() || service->IsConnected());

  if (disconnect_service) {
    LOG(INFO) << "Disconnecting from: " << service->log_name()
              << ": BSSRemoved";
    DisconnectFrom(service.get());
  }
}

void WiFi::CertificationTask(const KeyValueStore& properties) {
  // Events may come immediately after Stop().
  if (!enabled()) {
    return;
  }

  if (!current_service_) {
    LOG(ERROR) << "WiFi " << link_name() << " " << __func__
               << " with no current service.";
    return;
  }

  std::string subject;
  uint32_t depth;
  if (WPASupplicant::ExtractRemoteCertification(properties, &subject, &depth)) {
    current_service_->AddEAPCertification(subject, depth);
  }
}

void WiFi::EAPEventTask(const std::string& status,
                        const std::string& parameter) {
  // Events may come immediately after Stop().
  if (!enabled()) {
    return;
  }

  if (!current_service_) {
    LOG(ERROR) << "WiFi " << link_name() << " " << __func__
               << " with no current service.";
    return;
  }
  Service::ConnectFailure failure = Service::kFailureNone;
  eap_state_handler_->ParseStatus(status, parameter, &failure);
  if (failure == Service::kFailurePinMissing) {
    // wpa_supplicant can sometimes forget the PIN on disconnect from the AP.
    const std::string& pin = current_service_->eap()->pin();
    Error unused_error;
    RpcIdentifier rpcid =
        FindNetworkRpcidForService(current_service_.get(), &unused_error);
    if (!pin.empty() && !rpcid.value().empty()) {
      // We have a PIN configured, so we can provide it back to wpa_supplicant.
      LOG(INFO) << "Re-supplying PIN parameter to wpa_supplicant.";
      supplicant_interface_proxy_->NetworkReply(
          rpcid, WPASupplicant::kEAPRequestedParameterPin, pin);
      failure = Service::kFailureNone;
    }
  }
  if (failure != Service::kFailureNone) {
    // Avoid a reporting failure twice by resetting EAP state handler early.
    eap_state_handler_->Reset();
    pending_eap_failure_ = failure;
  }
}

void WiFi::PropertiesChangedTask(const KeyValueStore& properties) {
  // TODO(quiche): Handle changes in other properties (e.g. signal
  // strength).

  // Note that order matters here. In particular, we want to process
  // changes in the current BSS before changes in state. This is so
  // that we update the state of the correct Endpoint/Service.
  // Also note that events may occur (briefly) after Stop(), so we need to make
  // explicit decisions here on what to do when !enabled().
  if (enabled() && properties.Contains<RpcIdentifier>(
                       WPASupplicant::kInterfacePropertyCurrentBSS)) {
    CurrentBSSChanged(properties.Get<RpcIdentifier>(
        WPASupplicant::kInterfacePropertyCurrentBSS));
  }

  if (properties.Contains<std::string>(
          WPASupplicant::kInterfacePropertyState)) {
    StateChanged(
        properties.Get<std::string>(WPASupplicant::kInterfacePropertyState));

    // These properties should only be updated when there is a state change.
    if (properties.Contains<std::string>(
            WPASupplicant::kInterfacePropertyCurrentAuthMode)) {
      CurrentAuthModeChanged(properties.Get<std::string>(
          WPASupplicant::kInterfacePropertyCurrentAuthMode));
    }

    std::string suffix = GetSuffixFromAuthMode(supplicant_auth_mode_);
    if (!suffix.empty()) {
      if (properties.Contains<int32_t>(
              WPASupplicant::kInterfacePropertyRoamTime)) {
        // Network.Shill.WiFi.RoamTime.{PSK,FTPSK,EAP,FTEAP}
        metrics()->SendToUMA(
            base::StringPrintf("%s.%s", Metrics::kMetricWifiRoamTimePrefix,
                               suffix.c_str()),
            properties.Get<int32_t>(WPASupplicant::kInterfacePropertyRoamTime),
            Metrics::kMetricWifiRoamTimeMillisecondsMin,
            Metrics::kMetricWifiRoamTimeMillisecondsMax,
            Metrics::kMetricWifiRoamTimeNumBuckets);
      }

      if (properties.Contains<bool>(
              WPASupplicant::kInterfacePropertyRoamComplete)) {
        // Network.Shill.WiFi.RoamComplete.{PSK,FTPSK,EAP,FTEAP}
        metrics()->SendEnumToUMA(
            base::StringPrintf("%s.%s", Metrics::kMetricWifiRoamCompletePrefix,
                               suffix.c_str()),
            properties.Get<bool>(WPASupplicant::kInterfacePropertyRoamComplete)
                ? Metrics::kWiFiRoamSuccess
                : Metrics::kWiFiRoamFailure,
            Metrics::kWiFiRoamCompleteMax);
      }

      if (properties.Contains<int32_t>(
              WPASupplicant::kInterfacePropertySessionLength)) {
        // Network.Shill.WiFi.SessionLength.{PSK,FTPSK,EAP,FTEAP}
        metrics()->SendToUMA(
            base::StringPrintf("%s.%s", Metrics::kMetricWifiSessionLengthPrefix,
                               suffix.c_str()),
            properties.Get<int32_t>(
                WPASupplicant::kInterfacePropertySessionLength),
            Metrics::kMetricWifiSessionLengthMillisecondsMin,
            Metrics::kMetricWifiSessionLengthMillisecondsMax,
            Metrics::kMetricWifiSessionLengthNumBuckets);
      }
    }
  }

  if (properties.Contains<int32_t>(
          WPASupplicant::kInterfacePropertyAssocStatusCode)) {
    AssocStatusChanged(properties.Get<int32_t>(
        WPASupplicant::kInterfacePropertyAssocStatusCode));
  }

  if (properties.Contains<int32_t>(
          WPASupplicant::kInterfacePropertyAuthStatusCode)) {
    AuthStatusChanged(properties.Get<int32_t>(
        WPASupplicant::kInterfacePropertyAuthStatusCode));
  }

  if (properties.Contains<int32_t>(
          WPASupplicant::kInterfacePropertyDisconnectReason)) {
    DisconnectReasonChanged(properties.Get<int32_t>(
        WPASupplicant::kInterfacePropertyDisconnectReason));
  }
}

std::string WiFi::GetSuffixFromAuthMode(const std::string& auth_mode) const {
  if (auth_mode == WPASupplicant::kAuthModeWPAPSK ||
      auth_mode == WPASupplicant::kAuthModeWPA2PSK ||
      auth_mode == WPASupplicant::kAuthModeBothPSK) {
    return Metrics::kMetricWifiPSKSuffix;
  } else if (auth_mode == WPASupplicant::kAuthModeFTPSK) {
    return Metrics::kMetricWifiFTPSKSuffix;
  } else if (auth_mode == WPASupplicant::kAuthModeFTEAP) {
    return Metrics::kMetricWifiFTEAPSuffix;
  } else if (base::StartsWith(auth_mode, WPASupplicant::kAuthModeEAPPrefix,
                              base::CompareCase::SENSITIVE)) {
    return Metrics::kMetricWifiEAPSuffix;
  }
  return "";
}

void WiFi::ScanDoneTask() {
  SLOG(this, 2) << __func__ << " need_bss_flush_ " << need_bss_flush_;
  // Unsets this flag if it was set in InitiateScanInDarkResume since that scan
  // has completed.
  manager()->set_suppress_autoconnect(false);
  if (wake_on_wifi_) {
    wake_on_wifi_->OnScanCompleted();
  }
  // Post |UpdateScanStateAfterScanDone| so it runs after any pending scan
  // results have been processed.  This allows connections on new BSSes to be
  // started before we decide whether the scan was fruitful.
  dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&WiFi::UpdateScanStateAfterScanDone,
                                weak_ptr_factory_while_started_.GetWeakPtr()));
  if (wake_on_wifi_ && (provider_->NumAutoConnectableServices() < 1) &&
      IsIdle()) {
    // Ensure we are also idle in case we are in the midst of connecting to
    // the only service that was available for auto-connect on the previous
    // scan (which will cause it to show up as unavailable for auto-connect
    // when we query the WiFiProvider this time).
    wake_on_wifi_->OnNoAutoConnectableServicesAfterScan(
        provider_->GetSsidsConfiguredForAutoConnect(),
        base::Bind(&WiFi::RemoveSupplicantNetworks,
                   weak_ptr_factory_while_started_.GetWeakPtr()),
        base::Bind(&WiFi::TriggerPassiveScan,
                   weak_ptr_factory_while_started_.GetWeakPtr()));
  }
  if (need_bss_flush_) {
    CHECK(supplicant_interface_proxy_);
    // Compute |max_age| relative to |resumed_at_|, to account for the
    // time taken to scan.
    struct timeval now;
    uint32_t max_age;
    time_->GetTimeMonotonic(&now);
    max_age = kMaxBSSResumeAgeSeconds + (now.tv_sec - resumed_at_.tv_sec);
    supplicant_interface_proxy_->FlushBSS(max_age);
    need_bss_flush_ = false;
  }
  StartScanTimer();

  if (interworking_select_enabled_ && need_interworking_select_ &&
      hs20_bss_count_ != 0 && provider_->has_passpoint_credentials()) {
    LOG(INFO) << __func__ << " start interworking selection";
    // Interworking match is started only if a compatible access point is
    // around and there's credentials to match because such selection
    // takes time.
    supplicant_interface_proxy_->InterworkingSelect();
  }
  need_interworking_select_ = false;
}

void WiFi::ScanFailedTask() {
  SLOG(this, 2) << __func__;
  SetScanState(kScanIdle, kScanMethodNone, __func__);
}

void WiFi::UpdateScanStateAfterScanDone() {
  if (scan_method_ == kScanMethodFull) {
    // Only notify the Manager on completion of full scans, since the manager
    // will replace any cached geolocation info with the BSSes we have right
    // now.
    manager()->OnDeviceGeolocationInfoUpdated(this);
  }
  if (scan_state_ == kScanBackgroundScanning) {
    // Going directly to kScanIdle (instead of to kScanFoundNothing) inhibits
    // some UMA reporting in SetScanState.  That's desired -- we don't want
    // to report background scan results to UMA since the drivers may play
    // background scans over a longer period in order to not interfere with
    // traffic.
    SetScanState(kScanIdle, kScanMethodNone, __func__);
  } else if (scan_state_ != kScanIdle && IsIdle()) {
    SetScanState(kScanFoundNothing, scan_method_, __func__);
  }
}

void WiFi::GetAndUseInterfaceCapabilities() {
  KeyValueStore caps;

  if (!supplicant_interface_proxy_->GetCapabilities(&caps))
    LOG(ERROR) << "Failed to obtain interface capabilities";

  ConfigureScanSSIDLimit(caps);
}

void WiFi::ConfigureScanSSIDLimit(const KeyValueStore& caps) {
  if (caps.Contains<int>(WPASupplicant::kInterfaceCapabilityMaxScanSSID)) {
    int value = caps.Get<int>(WPASupplicant::kInterfaceCapabilityMaxScanSSID);
    SLOG(this, 2) << "Obtained MaxScanSSID capability: " << value;
    max_ssids_per_scan_ =
        std::min(static_cast<int>(WPASupplicant::kMaxMaxSSIDsPerScan),
                 std::max(0, value));
    if (max_ssids_per_scan_ != value)
      SLOG(this, 2) << "MaxScanSSID trimmed to: " << max_ssids_per_scan_;
  } else {
    LOG(WARNING) << "Missing MaxScanSSID capability, using default value: "
                 << WPASupplicant::kDefaultMaxSSIDsPerScan;
    max_ssids_per_scan_ = WPASupplicant::kDefaultMaxSSIDsPerScan;
  }

  if (max_ssids_per_scan_ <= 1)
    LOG(WARNING) << "MaxScanSSID <= 1, scans will alternate between single "
                 << "hidden SSID and broadcast scan.";
}

void WiFi::ScanTask() {
  SLOG(this, 2) << "WiFi " << link_name() << " scan requested.";
  if (!enabled()) {
    SLOG(this, 2) << "Ignoring scan request while device is not enabled.";
    SetScanState(kScanIdle, kScanMethodNone, __func__);  // Probably redundant.
    return;
  }
  if (!supplicant_present_ || !supplicant_interface_proxy_.get()) {
    SLOG(this, 2) << "Ignoring scan request while supplicant is not present.";
    SetScanState(kScanIdle, kScanMethodNone, __func__);
    return;
  }
  if ((pending_service_.get() && pending_service_->IsConnecting()) ||
      (current_service_.get() && current_service_->IsConnecting())) {
    SLOG(this, 2) << "Ignoring scan request while connecting to an AP.";
    return;
  }
  KeyValueStore scan_args;
  scan_args.Set<std::string>(WPASupplicant::kPropertyScanType,
                             WPASupplicant::kScanTypeActive);

  ByteArrays hidden_ssids = provider_->GetHiddenSSIDList();
  if (!hidden_ssids.empty()) {
    // Determine how many hidden ssids to pass in, based on max_ssids_per_scan_
    if (max_ssids_per_scan_ > 1) {
      // The empty '' "broadcast SSID" counts toward the max scan limit, so the
      // capability needs to be >= 2 to have at least 1 hidden SSID.
      if (hidden_ssids.size() >= static_cast<size_t>(max_ssids_per_scan_)) {
        // TODO(b/172220260): Devise a better method for time-sharing with SSIDs
        // that do not fit in
        hidden_ssids.erase(hidden_ssids.begin() + max_ssids_per_scan_ - 1,
                           hidden_ssids.end());
      }
      // Add Broadcast SSID, signified by an empty ByteArray.  If we specify
      // SSIDs to wpa_supplicant, we need to explicitly specify the default
      // behavior of doing a broadcast probe.
      hidden_ssids.push_back(ByteArray());

    } else if (max_ssids_per_scan_ == 1) {
      // Handle case where driver can only accept one scan_ssid at a time
      AlternateSingleScans(&hidden_ssids);
    } else {  // if max_ssids_per_scan_ < 1
      hidden_ssids.resize(0);
    }

    if (!hidden_ssids.empty()) {
      scan_args.Set<ByteArrays>(WPASupplicant::kPropertyScanSSIDs,
                                hidden_ssids);
    }
  }
  scan_args.Set<bool>(WPASupplicant::kPropertyScanAllowRoam,
                      manager()->scan_allow_roam());

  if (!supplicant_interface_proxy_->Scan(scan_args)) {
    // A scan may fail if, for example, the wpa_supplicant vanishing
    // notification is posted after this task has already started running.
    LOG(WARNING) << "Scan failed";
    return;
  }

  // Only set the scan state/method if we are starting a full scan from
  // scratch.
  if (scan_state_ != kScanScanning) {
    SetScanState(IsIdle() ? kScanScanning : kScanBackgroundScanning,
                 kScanMethodFull, __func__);
  }
}

void WiFi::AlternateSingleScans(ByteArrays* hidden_ssids) {
  // Ensure at least one hidden SSID is probed.
  if (broadcast_probe_was_skipped_) {
    SLOG(this, 2) << "Doing broadcast probe instead of directed probe.";
    hidden_ssids->resize(0);
  } else {
    SLOG(this, 2) << "Doing directed probe instead of broadcast probe.";
    hidden_ssids->resize(1);
  }
  broadcast_probe_was_skipped_ = !broadcast_probe_was_skipped_;
}

std::string WiFi::GetServiceLeaseName(const WiFiService& service) {
  return service.GetStorageIdentifier();
}

const WiFiEndpointConstRefPtr WiFi::GetCurrentEndpoint() const {
  EndpointMap::const_iterator endpoint_it =
      endpoint_by_rpcid_.find(supplicant_bss_);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    return nullptr;
  }

  return endpoint_it->second.get();
}

void WiFi::DestroyServiceLease(const WiFiService& service) {
  DestroyIPConfigLease(GetServiceLeaseName(service));
}

void WiFi::StateChanged(const std::string& new_state) {
  const std::string old_state = supplicant_state_;
  supplicant_state_ = new_state;
  LOG(INFO) << "WiFi " << link_name() << " " << __func__ << " " << old_state
            << " -> " << new_state;

  if (old_state == WPASupplicant::kInterfaceStateDisconnected &&
      new_state != WPASupplicant::kInterfaceStateDisconnected) {
    // The state has been changed from disconnect to something else, clearing
    // out disconnect reason to avoid confusion about future disconnects.
    SLOG(this, 3) << "WiFi clearing DisconnectReason for " << link_name();
    supplicant_disconnect_reason_ = IEEE_80211::kReasonCodeInvalid;
  }

  // Identify the service to which the state change applies. If
  // |pending_service_| is non-NULL, then the state change applies to
  // |pending_service_|. Otherwise, it applies to |current_service_|.
  //
  // This policy is driven by the fact that the |pending_service_|
  // doesn't become the |current_service_| until wpa_supplicant
  // reports a CurrentBSS change to the |pending_service_|. And the
  // CurrentBSS change won't be reported until the |pending_service_|
  // reaches the WPASupplicant::kInterfaceStateCompleted state.
  WiFiService* affected_service =
      pending_service_.get() ? pending_service_.get() : current_service_.get();
  if (!affected_service) {
    SLOG(this, 2) << "WiFi " << link_name() << " " << __func__
                  << " with no service";
    return;
  }

  if (new_state == WPASupplicant::kInterfaceStateCompleted) {
    if (!IsStateTransitionConnectionMaintenance(*affected_service)) {
      // Do not report connection attempts when the transition to
      // |kInterfaceStateCompleted| was caused by a "maintenance" event
      // (e.g. rekeying) from a fully connected state rather than a genuine
      // attempt to connect from a "disconnected" state.
      metrics()->NotifyWiFiConnectionAttemptResult(
          Metrics::kNetworkServiceErrorNone);
    }
    if (affected_service->IsConnected()) {
      StopReconnectTimer();
      if (is_roaming_in_progress_) {
        // This means wpa_supplicant completed a roam without an intervening
        // disconnect. We should renew our DHCP lease just in case the new
        // AP is on a different subnet than where we started.
        // TODO(matthewmwang): Handle the IPv6 roam case.
        is_roaming_in_progress_ = false;
        if (dhcp_controller()) {
          LOG(INFO) << link_name() << " renewing L3 configuration after roam.";
          dhcp_controller()->RenewIP();
          affected_service->SetRoamState(Service::kRoamStateConfiguring);
        }
      } else if (affected_service->is_rekey_in_progress()) {
        affected_service->SetIsRekeyInProgress(false);
        LOG(INFO) << link_name()
                  << " EAP re-key complete. No need to renew L3 configuration.";
      }
    } else if (has_already_completed_) {
      LOG(INFO) << link_name() << " L3 configuration already started.";
    } else {
      if (AcquireIPConfigWithLeaseName(
              GetServiceLeaseName(*affected_service))) {
        LOG(INFO) << link_name() << " is up; started L3 configuration.";
        affected_service->SetState(Service::kStateConfiguring);
        if (affected_service->IsSecurityMatch(kSecurityWep)) {
          // With the overwhelming majority of WEP networks, we cannot assume
          // our credentials are correct just because we have successfully
          // connected.  It is more useful to track received data as the L3
          // configuration proceeds to see if we can decrypt anything.
          receive_byte_count_at_connect_ = GetReceiveByteCount();
        } else {
          affected_service->ResetSuspectedCredentialFailures();
        }
      } else {
        LOG(ERROR) << "Unable to acquire DHCP config.";
      }
    }
    has_already_completed_ = true;
  } else if (IsWPAStateConnectionInProgress(new_state)) {
    if (new_state == WPASupplicant::kInterfaceStateAssociating) {
      // Ensure auth status is kept up-to-date
      supplicant_auth_status_ = IEEE_80211::kStatusCodeSuccessful;
    } else if (new_state == WPASupplicant::kInterfaceStateAssociated) {
      // Supplicant does not indicate successful association in assoc status
      // messages, but we know at this point that 802.11 association succeeded
      supplicant_assoc_status_ = IEEE_80211::kStatusCodeSuccessful;
    }

    if (is_roaming_in_progress_) {
      // Instead of transitioning into the associating state and potentially
      // reordering the service list, set the roam state to keep track of the
      // actual state.
      affected_service->SetRoamState(Service::kRoamStateAssociating);
    } else if (!affected_service->is_rekey_in_progress()) {
      // Ignore transitions into these states when roaming is in progress, to
      // avoid bothering the user when roaming, or re-keying.
      if (old_state == WPASupplicant::kInterfaceStateCompleted) {
        // Shill gets EAP events when a re-key happens in an 802.1X network, but
        // nothing when it happens in a PSK network. Unless roaming is in
        // progress, we assume supplicant state transitions from completed to an
        // auth/assoc state are a result of a re-key.
        affected_service->SetIsRekeyInProgress(true);
      } else {
        affected_service->SetState(Service::kStateAssociating);
      }
    }
    // TODO(quiche): On backwards transitions, we should probably set
    // a timeout for getting back into the completed state. At present,
    // we depend on wpa_supplicant eventually reporting that CurrentBSS
    // has changed. But there may be cases where that signal is not sent.
    // (crbug.com/206208)
  } else if (new_state == WPASupplicant::kInterfaceStateDisconnected &&
             affected_service == current_service_ &&
             affected_service->IsConnected()) {
    // This means that wpa_supplicant failed in a re-connect attempt, but
    // may still be reconnecting.  Give wpa_supplicant a limited amount of
    // time to transition out this condition by either connecting or changing
    // CurrentBSS.
    StartReconnectTimer();
  } else {
    // Other transitions do not affect Service state.
    //
    // Note in particular that we ignore a State change into
    // kInterfaceStateDisconnected, in favor of observing the corresponding
    // change in CurrentBSS.
  }
}

bool WiFi::SuspectCredentials(WiFiServiceRefPtr service,
                              Service::ConnectFailure* failure) const {
  if (service->IsSecurityMatch(kSecurityPsk)) {
    if (supplicant_state_ == WPASupplicant::kInterfaceState4WayHandshake &&
        service->AddSuspectedCredentialFailure()) {
      if (failure) {
        *failure = Service::kFailureBadPassphrase;
      }
      return true;
    }
  } else if (service->IsSecurityMatch(kSecurity8021x)) {
    if (eap_state_handler_->is_eap_in_progress() &&
        service->AddSuspectedCredentialFailure()) {
      if (failure) {
        *failure = Service::kFailureEAPAuthentication;
      }
      return true;
    }
  }

  return false;
}

// static
bool WiFi::SanitizeSSID(std::string* ssid) {
  CHECK(ssid);

  size_t ssid_len = ssid->length();
  size_t i;
  bool changed = false;

  for (i = 0; i < ssid_len; ++i) {
    if (!IsPrintableAsciiChar((*ssid)[i])) {
      (*ssid)[i] = '?';
      changed = true;
    }
  }

  return changed;
}

// static
std::string WiFi::LogSSID(const std::string& ssid) {
  std::string out;
  for (const auto& chr : ssid) {
    // Replace '[' and ']' (in addition to non-printable characters) so that
    // it's easy to match the right substring through a non-greedy regex.
    if (chr == '[' || chr == ']' || !IsPrintableAsciiChar(chr)) {
      base::StringAppendF(&out, "\\x%02x", chr);
    } else {
      out += chr;
    }
  }
  return base::StringPrintf("[SSID=%s]", out.c_str());
}

void WiFi::OnUnreliableLink() {
  SLOG(this, 2) << "Device " << link_name() << ": Link is unreliable.";
  selected_service()->set_unreliable(true);
  reliable_link_callback_.Cancel();
  metrics()->NotifyUnreliableLinkSignalStrength(Technology::kWiFi,
                                                selected_service()->strength());
}

void WiFi::OnReliableLink() {
  SLOG(this, 2) << "Device " << link_name() << ": Link is reliable.";
  selected_service()->set_unreliable(false);
}

void WiFi::OnLinkMonitorFailure(IPAddress::Family family) {
  SLOG(this, 2) << "Device " << link_name()
                << ": Link Monitor indicates failure.";

  // Determine the reliability of the link.
  time_t now;
  time_->GetSecondsBoottime(&now);
  if (last_link_monitor_failed_time_ != 0 &&
      now - last_link_monitor_failed_time_ <
          kLinkUnreliableThreshold.InSeconds()) {
    OnUnreliableLink();
  }
  last_link_monitor_failed_time_ = now;

  // If we have never found the gateway, let's be conservative and not
  // do anything, in case this network topology does not have a gateway.
  if ((family == IPAddress::kFamilyIPv4 && !ipv4_gateway_found_) ||
      (family == IPAddress::kFamilyIPv6 && !ipv6_gateway_found_)) {
    LOG(INFO) << "In " << __func__ << "(): "
              << "Skipping reassociate since gateway was never found.";
    return;
  }

  if (!supplicant_present_) {
    LOG(ERROR) << "In " << __func__ << "(): "
               << "wpa_supplicant is not present.  Cannot reassociate.";
    return;
  }

  if (!current_service_) {
    LOG(INFO) << "No current service, skipping reassociate attempt.";
    return;
  }

  // Skip reassociate attempt if service is not reliable, meaning multiple link
  // failures in short period of time.
  if (current_service_->unreliable()) {
    LOG(INFO) << "Current service is unreliable, skipping reassociate attempt.";

    // We only want to capture the scenario where we see the network become
    // unreliable soon after a rekey.
    int seconds =
        (base::Time::Now() - current_service_->last_rekey_time()).InSeconds();
    if (seconds < Metrics::kMetricTimeFromRekeyToFailureSecondsMax) {
      LOG(INFO) << "Connection became unreliable shortly after rekey, "
                << "seconds between rekey and connection failure: " << seconds;
      metrics()->NotifyWiFiServiceFailureAfterRekey(seconds);
    }
    return;
  }

  // This will force a transition out of connected, if we are actually
  // connected.
  if (!supplicant_interface_proxy_->Reattach()) {
    LOG(ERROR) << "In " << __func__ << "(): failed to call Reattach().";
    return;
  }

  // If we don't eventually get a transition back into a connected state,
  // there is something wrong.
  StartReconnectTimer();
  LOG(INFO) << "In " << __func__ << "(): Called Reattach().";
}

bool WiFi::ShouldUseArpGateway() const {
  return !IsUsingStaticIP();
}

void WiFi::DisassociateFromService(const WiFiServiceRefPtr& service) {
  SLOG(this, 2) << "In " << __func__ << " for service: " << service->log_name();
  DisconnectFromIfActive(service.get());
  if (service == selected_service()) {
    DropConnection();
  }
  Error unused_error;
  RemoveNetworkForService(service.get(), &unused_error);
}

std::vector<GeolocationInfo> WiFi::GetGeolocationObjects() const {
  std::vector<GeolocationInfo> objects;
  for (const auto& endpoint_entry : endpoint_by_rpcid_) {
    GeolocationInfo geoinfo;
    const WiFiEndpointRefPtr& endpoint = endpoint_entry.second;
    geoinfo[kGeoMacAddressProperty] = endpoint->bssid_string();
    geoinfo[kGeoSignalStrengthProperty] =
        base::StringPrintf("%d", endpoint->signal_strength());
    geoinfo[kGeoChannelProperty] = base::StringPrintf(
        "%d", Metrics::WiFiFrequencyToChannel(endpoint->frequency()));
    AddLastSeenTime(&geoinfo, endpoint->last_seen());
    objects.push_back(geoinfo);
  }
  return objects;
}

void WiFi::HelpRegisterDerivedInt32(PropertyStore* store,
                                    const std::string& name,
                                    int32_t (WiFi::*get)(Error* error),
                                    bool (WiFi::*set)(const int32_t& value,
                                                      Error* error)) {
  store->RegisterDerivedInt32(
      name, Int32Accessor(new CustomAccessor<WiFi, int32_t>(this, get, set)));
}

void WiFi::HelpRegisterDerivedUint16(PropertyStore* store,
                                     const std::string& name,
                                     uint16_t (WiFi::*get)(Error* error),
                                     bool (WiFi::*set)(const uint16_t& value,
                                                       Error* error)) {
  store->RegisterDerivedUint16(
      name, Uint16Accessor(new CustomAccessor<WiFi, uint16_t>(this, get, set)));
}

void WiFi::HelpRegisterDerivedBool(PropertyStore* store,
                                   const std::string& name,
                                   bool (WiFi::*get)(Error* error),
                                   bool (WiFi::*set)(const bool& value,
                                                     Error* error)) {
  store->RegisterDerivedBool(
      name, BoolAccessor(new CustomAccessor<WiFi, bool>(this, get, set)));
}

void WiFi::HelpRegisterConstDerivedBool(PropertyStore* store,
                                        const std::string& name,
                                        bool (WiFi::*get)(Error* error)) {
  store->RegisterDerivedBool(
      name, BoolAccessor(new CustomAccessor<WiFi, bool>(this, get, nullptr)));
}

void WiFi::HelpRegisterConstDerivedUint16s(PropertyStore* store,
                                           const std::string& name,
                                           Uint16s (WiFi::*get)(Error* error)) {
  store->RegisterDerivedUint16s(
      name,
      Uint16sAccessor(new CustomAccessor<WiFi, Uint16s>(this, get, nullptr)));
}

void WiFi::OnBeforeSuspend(const ResultCallback& callback) {
  if (!enabled()) {
    callback.Run(Error(Error::kSuccess));
    return;
  }
  LOG(INFO) << __func__ << ": "
            << (IsConnectedToCurrentService() ? "connected" : "not connected");
  StopScanTimer();
  supplicant_process_proxy()->ExpectDisconnect();
  if (!wake_on_wifi_) {
    callback.Run(Error(Error::kSuccess));
    return;
  }
  wake_on_wifi_->OnBeforeSuspend(
      IsConnectedToCurrentService(),
      provider_->GetSsidsConfiguredForAutoConnect(), callback,
      base::Bind(&Device::RenewDHCPLease,
                 weak_ptr_factory_while_started_.GetWeakPtr(), false, nullptr),
      base::Bind(&WiFi::RemoveSupplicantNetworks,
                 weak_ptr_factory_while_started_.GetWeakPtr()),
      TimeToNextDHCPLeaseRenewal());
}

void WiFi::OnDarkResume(const ResultCallback& callback) {
  if (!enabled()) {
    callback.Run(Error(Error::kSuccess));
    return;
  }
  LOG(INFO) << __func__ << ": "
            << (IsConnectedToCurrentService() ? "connected" : "not connected");
  StopScanTimer();
  if (!wake_on_wifi_) {
    callback.Run(Error(Error::kSuccess));
    return;
  }
  wake_on_wifi_->OnDarkResume(
      IsConnectedToCurrentService(),
      provider_->GetSsidsConfiguredForAutoConnect(), callback,
      base::Bind(&Device::RenewDHCPLease,
                 weak_ptr_factory_while_started_.GetWeakPtr(), false, nullptr),
      base::Bind(&WiFi::InitiateScanInDarkResume,
                 weak_ptr_factory_while_started_.GetWeakPtr()),
      base::Bind(&WiFi::RemoveSupplicantNetworks,
                 weak_ptr_factory_while_started_.GetWeakPtr()));
}

void WiFi::OnAfterResume() {
  LOG(INFO) << __func__ << ": "
            << (IsConnectedToCurrentService() ? "connected" : "not connected")
            << ", " << (enabled() ? "enabled" : "disabled");
  Device::OnAfterResume();  // May refresh ipconfig_
  // We let the Device class do its thing, but we did nothing in
  // OnBeforeSuspend(), so why undo anything now?
  if (!enabled()) {
    return;
  }
  dispatcher()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&WiFi::ReportConnectedToServiceAfterWake,
                     weak_ptr_factory_while_started_.GetWeakPtr()),
      kPostWakeConnectivityReportDelay);
  if (wake_on_wifi_) {
    wake_on_wifi_->OnAfterResume();
  }

  // We want to flush the BSS cache, but we don't want to conflict
  // with an active connection attempt. So record the need to flush,
  // and take care of flushing when the next scan completes.
  //
  // Note that supplicant will automatically expire old cache
  // entries (after, e.g., a BSS is not found in two consecutive
  // scans). However, our explicit flush accelerates re-association
  // in cases where a BSS disappeared while we were asleep. (See,
  // e.g. WiFiRoaming.005SuspendRoam.)
  time_->GetTimeMonotonic(&resumed_at_);
  need_bss_flush_ = true;

  if (!IsConnectedToCurrentService()) {
    InitiateScan();
  }

  // Since we stopped the scan timer before suspending, start it again here.
  StartScanTimer();

  // Resume from sleep, could be in different location now.
  // Ignore previous link monitor failures.
  if (selected_service()) {
    selected_service()->set_unreliable(false);
    reliable_link_callback_.Cancel();
  }
  last_link_monitor_failed_time_ = 0;
}

void WiFi::AbortScan() {
  SetScanState(kScanIdle, kScanMethodNone, __func__);
}

void WiFi::InitiateScan() {
  LOG(INFO) << __func__;
  // Abort any current scan (at the shill-level; let any request that's
  // already gone out finish) since we don't know when it started.
  AbortScan();

  if (IsIdle()) {
    // Not scanning/connecting/connected, so let's get things rolling.
    Scan(nullptr, __func__);
    RestartFastScanAttempts();
  } else {
    SLOG(this, 1) << __func__
                  << " skipping scan, already connecting or connected.";
  }
}

void WiFi::InitiateScanInDarkResume(const FreqSet& freqs) {
  LOG(INFO) << __func__;
  AbortScan();
  if (!IsIdle()) {
    SLOG(this, 1) << __func__
                  << " skipping scan, already connecting or connected.";
    return;
  }

  CHECK(supplicant_interface_proxy_);
  // Force complete flush of BSS cache since we want WPA supplicant and shill to
  // have an accurate view of what endpoints are available in dark resume. This
  // prevents either from performing incorrect actions that can prolong dark
  // resume (e.g. attempting to auto-connect to a WiFi service whose endpoint
  // disappeared before the dark resume).
  if (!supplicant_interface_proxy_->FlushBSS(0)) {
    LOG(WARNING) << __func__ << ": Failed to flush wpa_supplicant BSS cache";
  }
  // Suppress any autoconnect attempts until this scan is done and endpoints
  // are updated.
  manager()->set_suppress_autoconnect(true);

  TriggerPassiveScan(freqs);
}

void WiFi::TriggerPassiveScan(const FreqSet& freqs) {
  LOG(INFO) << __func__;
  TriggerScanMessage trigger_scan;
  trigger_scan.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                                  interface_index());
  if (!freqs.empty()) {
    SLOG(this, 3) << __func__ << ": "
                  << "Scanning on specific channels";
    trigger_scan.attributes()->CreateNl80211Attribute(
        NL80211_ATTR_SCAN_FREQUENCIES, NetlinkMessage::MessageContext());

    AttributeListRefPtr frequency_list;
    if (!trigger_scan.attributes()->GetNestedAttributeList(
            NL80211_ATTR_SCAN_FREQUENCIES, &frequency_list) ||
        !frequency_list) {
      LOG(ERROR) << __func__ << ": "
                 << "Couldn't get NL80211_ATTR_SCAN_FREQUENCIES";
    }
    trigger_scan.attributes()->SetNestedAttributeHasAValue(
        NL80211_ATTR_SCAN_FREQUENCIES);

    std::string attribute_name;
    int i = 0;
    for (uint32_t freq : freqs) {
      SLOG(this, 7) << __func__ << ": "
                    << "Frequency-" << i << ": " << freq;
      attribute_name = base::StringPrintf("Frequency-%d", i);
      frequency_list->CreateU32Attribute(i, attribute_name.c_str());
      frequency_list->SetU32AttributeValue(i, freq);
      ++i;
    }
  }

  netlink_manager_->SendNl80211Message(
      &trigger_scan,
      base::Bind(&WiFi::OnTriggerPassiveScanResponse,
                 weak_ptr_factory_while_started_.GetWeakPtr()),
      base::Bind(&NetlinkManager::OnAckDoNothing),
      base::Bind(&NetlinkManager::OnNetlinkMessageError));
}

void WiFi::OnConnected() {
  Device::OnConnected();
  if (current_service_ && current_service_->IsSecurityMatch(kSecurityWep)) {
    // With a WEP network, we are now reasonably certain the credentials are
    // correct, whereas with other network types we were able to determine
    // this earlier when the association process succeeded.
    current_service_->ResetSuspectedCredentialFailures();
  }
  RequestStationInfo();

  // Clears the link monitor states for the previous connection.
  ipv4_gateway_found_ = false;
  ipv6_gateway_found_ = false;

  if (selected_service()->unreliable()) {
    // Post a delayed task to reset link back to reliable if no link failure is
    // detected in the next 5 minutes.
    reliable_link_callback_.Reset(
        base::Bind(&WiFi::OnReliableLink, base::Unretained(this)));
    dispatcher()->PostDelayedTask(FROM_HERE, reliable_link_callback_.callback(),
                                  kLinkUnreliableResetTimeout);
  }
}

void WiFi::OnSelectedServiceChanged(const ServiceRefPtr& old_service) {
  // Reset link status for the previously selected service.
  if (old_service) {
    old_service->set_unreliable(false);
  }
  reliable_link_callback_.Cancel();
  last_link_monitor_failed_time_ = 0;
}

void WiFi::OnIPConfigFailure() {
  if (!current_service_) {
    LOG(ERROR) << "WiFi " << link_name() << " " << __func__
               << " with no current service.";
    return;
  }
  if (current_service_->IsSecurityMatch(kSecurityWep) &&
      GetReceiveByteCount() == receive_byte_count_at_connect_ &&
      current_service_->AddSuspectedCredentialFailure()) {
    // If we've connected to a WEP network and haven't successfully
    // decrypted any bytes at all during the configuration process,
    // it is fair to suspect that our credentials to this network
    // may not be correct.
    Error error;
    current_service_->DisconnectWithFailure(Service::kFailureBadPassphrase,
                                            &error, __func__);
    return;
  }

  Device::OnIPConfigFailure();
}

void WiFi::RestartFastScanAttempts() {
  if (!enabled()) {
    SLOG(this, 2) << "Skpping fast scan attempts while not enabled.";
    return;
  }
  fast_scans_remaining_ = kNumFastScanAttempts;
  StartScanTimer();
}

void WiFi::StartScanTimer() {
  SLOG(this, 2) << __func__;
  if (scan_interval_seconds_ == 0) {
    StopScanTimer();
    return;
  }
  scan_timer_callback_.Reset(base::Bind(
      &WiFi::ScanTimerHandler, weak_ptr_factory_while_started_.GetWeakPtr()));
  // Repeat the first few scans after disconnect relatively quickly so we
  // have reasonable trust that no APs we are looking for are present.
  base::TimeDelta wait_time = fast_scans_remaining_ > 0
                                  ? kFastScanInterval
                                  : base::Seconds(scan_interval_seconds_);
  dispatcher()->PostDelayedTask(FROM_HERE, scan_timer_callback_.callback(),
                                wait_time);
  SLOG(this, 5) << "Next scan scheduled for " << wait_time.InMilliseconds()
                << "ms";
}

void WiFi::StopScanTimer() {
  SLOG(this, 2) << __func__;
  scan_timer_callback_.Cancel();
}

void WiFi::ScanTimerHandler() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  if (manager()->IsSuspending()) {
    SLOG(this, 5) << "Not scanning: still in suspend";
    return;
  }
  if (scan_state_ == kScanIdle && IsIdle()) {
    Scan(nullptr, __func__);
    if (fast_scans_remaining_ > 0) {
      --fast_scans_remaining_;
    }
  } else {
    if (scan_state_ != kScanIdle) {
      SLOG(this, 5) << "Skipping scan: scan_state_ is " << scan_state_;
    }
    if (current_service_) {
      SLOG(this, 5) << "Skipping scan: current_service_ is service "
                    << current_service_->log_name();
    }
    if (pending_service_) {
      SLOG(this, 5) << "Skipping scan: pending_service_ is service"
                    << pending_service_->log_name();
    }
  }
  StartScanTimer();
}

void WiFi::StartPendingTimer() {
  pending_timeout_callback_.Reset(
      base::Bind(&WiFi::PendingTimeoutHandler,
                 weak_ptr_factory_while_started_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(FROM_HERE, pending_timeout_callback_.callback(),
                                kPendingTimeout);
}

void WiFi::StopPendingTimer() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  pending_timeout_callback_.Cancel();
}

void WiFi::SetPendingService(const WiFiServiceRefPtr& service) {
  SLOG(this, 2) << "WiFi " << link_name() << " setting pending service to "
                << (service ? service->log_name() : "<none>");
  if (service) {
    SetScanState(kScanConnecting, scan_method_, __func__);
    service->SetState(Service::kStateAssociating);
    StartPendingTimer();
  } else {
    // SetPendingService(nullptr) is called in the following cases:
    //  a) |ConnectTo|->|DisconnectFrom|.  Connecting to a service, disconnect
    //     the old service (scan_state_ == kScanTransitionToConnecting).  No
    //     state transition is needed here.
    //  b) |HandleRoam|.  Connected to a service, it's no longer pending
    //     (scan_state_ == kScanIdle).  No state transition is needed here.
    //  c) |DisconnectFrom| and |HandleDisconnect|. Disconnected/disconnecting
    //     from a service not during a scan (scan_state_ == kScanIdle).  No
    //     state transition is needed here.
    //  d) |DisconnectFrom| and |HandleDisconnect|. Disconnected/disconnecting
    //     from a service during a scan (scan_state_ == kScanScanning or
    //     kScanConnecting).  This is an odd case -- let's discard any
    //     statistics we're gathering by transitioning directly into kScanIdle.
    if (scan_state_ == kScanScanning ||
        scan_state_ == kScanBackgroundScanning ||
        scan_state_ == kScanConnecting) {
      SetScanState(kScanIdle, kScanMethodNone, __func__);
    }
    if (pending_service_) {
      StopPendingTimer();
    }
  }
  pending_service_ = service;
}

void WiFi::PendingTimeoutHandler() {
  Error unused_error;
  LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__;
  CHECK(pending_service_);
  SetScanState(kScanFoundNothing, scan_method_, __func__);
  WiFiServiceRefPtr pending_service = pending_service_;

  SLOG(this, 4) << "Supplicant authentication status: "
                << supplicant_auth_status_;
  SLOG(this, 4) << "Supplicant association status: "
                << supplicant_assoc_status_;

  Service::ConnectFailure failure = ExamineStatusCodes();
  if (failure == Service::kFailureUnknown && pending_service_ &&
      SignalOutOfRange(pending_service_->SignalLevel())) {
    failure = Service::kFailureOutOfRange;
  }
  pending_service_->DisconnectWithFailure(failure, &unused_error, __func__);

  // A hidden service may have no endpoints, since wpa_supplicant
  // failed to attain a CurrentBSS.  If so, the service has no
  // reference to |this| device and cannot call WiFi::DisconnectFrom()
  // to reset pending_service_.  In this case, we must perform the
  // disconnect here ourselves.
  if (pending_service_) {
    CHECK(!pending_service_->HasEndpoints());
    LOG(INFO) << "Hidden service was not found.";
    DisconnectFrom(pending_service_.get());
  }

  // DisconnectWithFailure will leave the pending service's state in failure
  // state. Reset its state back to idle, to allow it to be connectable again.
  pending_service->SetState(Service::kStateIdle);
}

void WiFi::StartReconnectTimer() {
  if (!reconnect_timeout_callback_.IsCancelled()) {
    LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__
              << ": reconnect timer already running.";
    return;
  }
  LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__;
  reconnect_timeout_callback_.Reset(
      base::Bind(&WiFi::ReconnectTimeoutHandler,
                 weak_ptr_factory_while_started_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(
      FROM_HERE, reconnect_timeout_callback_.callback(), kReconnectTimeout);
}

void WiFi::StopReconnectTimer() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  reconnect_timeout_callback_.Cancel();
}

void WiFi::ReconnectTimeoutHandler() {
  LOG(INFO) << "WiFi Device " << link_name() << ": " << __func__;
  reconnect_timeout_callback_.Cancel();
  CHECK(current_service_);
  current_service_->SetFailure(Service::kFailureConnect);
  DisconnectFrom(current_service_.get());
}

void WiFi::OnSupplicantPresence(bool present) {
  LOG(INFO) << "WPA supplicant presence changed: " << present;

  if (present) {
    if (supplicant_present_) {
      // Restart the WiFi device if it's started already. This will reset the
      // state and connect the device to the new WPA supplicant instance.
      if (enabled()) {
        Restart();
      }
      return;
    }
    supplicant_present_ = true;
    ConnectToSupplicant();
    return;
  }

  if (!supplicant_present_) {
    return;
  }
  supplicant_present_ = false;
  // Restart the WiFi device if it's started already. This will effectively
  // suspend the device until the WPA supplicant reappears.
  if (enabled()) {
    Restart();
  }
}

void WiFi::OnWiFiDebugScopeChanged(bool enabled) {
  SLOG(this, 2) << "WiFi debug scope changed; enable is now " << enabled;
  if (!Device::enabled() || !supplicant_present_) {
    SLOG(this, 2) << "Supplicant process proxy not connected.";
    return;
  }
  std::string current_level;
  if (!supplicant_process_proxy()->GetDebugLevel(&current_level)) {
    LOG(ERROR) << __func__ << ": Failed to get wpa_supplicant debug level.";
    return;
  }

  if (current_level != WPASupplicant::kDebugLevelInfo &&
      current_level != WPASupplicant::kDebugLevelDebug) {
    SLOG(this, 2) << "WiFi debug level is currently " << current_level
                  << "; assuming that it is being controlled elsewhere.";
    return;
  }
  std::string new_level = enabled ? WPASupplicant::kDebugLevelDebug
                                  : WPASupplicant::kDebugLevelInfo;

  if (new_level == current_level) {
    SLOG(this, 2) << "WiFi debug level is already the desired level "
                  << current_level;
    return;
  }

  if (!supplicant_process_proxy()->SetDebugLevel(new_level)) {
    LOG(ERROR) << __func__ << ": Failed to set wpa_supplicant debug level.";
  }
}

void WiFi::SetConnectionDebugging(bool enabled) {
  if (is_debugging_connection_ == enabled) {
    return;
  }
  OnWiFiDebugScopeChanged(enabled || ScopeLogger::GetInstance()->IsScopeEnabled(
                                         ScopeLogger::kWiFi));
  is_debugging_connection_ = enabled;
}

void WiFi::SetSupplicantInterfaceProxy(
    std::unique_ptr<SupplicantInterfaceProxyInterface> proxy) {
  if (proxy) {
    supplicant_interface_proxy_ = std::move(proxy);
  } else {
    supplicant_interface_proxy_.reset();
  }
}

void WiFi::ConnectToSupplicant() {
  LOG(INFO) << link_name() << ": " << (enabled() ? "enabled" : "disabled")
            << " supplicant: " << (supplicant_present_ ? "present" : "absent")
            << " proxy: "
            << (supplicant_interface_proxy_.get() ? "non-null" : "null");
  if (!enabled() || !supplicant_present_) {
    return;
  }
  OnWiFiDebugScopeChanged(
      ScopeLogger::GetInstance()->IsScopeEnabled(ScopeLogger::kWiFi));

  RpcIdentifier previous_supplicant_interface_path(supplicant_interface_path_);

  KeyValueStore create_interface_args;
  create_interface_args.Set<std::string>(WPASupplicant::kInterfacePropertyName,
                                         link_name());
  create_interface_args.Set<std::string>(
      WPASupplicant::kInterfacePropertyDriver, WPASupplicant::kDriverNL80211);
  create_interface_args.Set<std::string>(
      WPASupplicant::kInterfacePropertyConfigFile,
      WPASupplicant::kSupplicantConfPath);
  supplicant_connect_attempts_++;
  if (!supplicant_process_proxy()->CreateInterface(
          create_interface_args, &supplicant_interface_path_)) {
    // Interface might've already been created, attempt to retrieve it.
    if (!supplicant_process_proxy()->GetInterface(
            link_name(), &supplicant_interface_path_)) {
      LOG(WARNING) << __func__
                   << ": Failed to create interface with supplicant, attempt "
                   << supplicant_connect_attempts_;

      // Interface could not be created at the moment. This could be a
      // transient error in trying to bring the interface UP, or it could be a
      // persistent device failure. We continue to rety a few times until
      // either we succeed or the device disappears or is disabled, in the hope
      // that the device will recover.
      if (supplicant_connect_attempts_ >= kMaxRetryCreateInterfaceAttempts) {
        LOG(ERROR) << "Failed to create interface with supplicant after "
                   << supplicant_connect_attempts_ << " attempts. Giving up.";
        SetEnabled(false);
        metrics()->NotifyWiFiSupplicantAbort();
      } else {
        dispatcher()->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&WiFi::ConnectToSupplicant,
                           weak_ptr_factory_.GetWeakPtr()),
            kRetryCreateInterfaceInterval);
      }
      return;
    }
  }

  LOG(INFO) << "connected to supplicant on attempt "
            << supplicant_connect_attempts_;
  metrics()->NotifyWiFiSupplicantSuccess(supplicant_connect_attempts_);

  // Only (re)create the interface proxy if its D-Bus path changed, or if we
  // haven't created one yet. This lets us watch interface properties
  // immediately after Stop() (e.g., for metrics collection) and also allows
  // tests to skip recreation (by retaining the same interface path).
  if (!supplicant_interface_proxy_ ||
      previous_supplicant_interface_path != supplicant_interface_path_) {
    SLOG(this, 2) << base::StringPrintf(
        "Updating interface path from \"%s\" to \"%s\"",
        previous_supplicant_interface_path.value().c_str(),
        supplicant_interface_path_.value().c_str());
    SetSupplicantInterfaceProxy(
        control_interface()->CreateSupplicantInterfaceProxy(
            this, supplicant_interface_path_));
  } else {
    SLOG(this, 2) << "Reusing existing interface at "
                  << supplicant_interface_path_.value();
  }

  GetAndUseInterfaceCapabilities();

  RTNLHandler::GetInstance()->SetInterfaceFlags(interface_index(), IFF_UP,
                                                IFF_UP);
  // TODO(quiche) Set ApScan=1 and BSSExpireAge=190, like flimflam does?

  // Clear out any networks that might previously have been configured
  // for this interface.
  supplicant_interface_proxy_->RemoveAllNetworks();

  // Flush interface's BSS cache, so that we get BSSAdded signals for
  // all BSSes (not just new ones since the last scan).
  supplicant_interface_proxy_->FlushBSS(0);

  // TODO(pstew): Disable fast_reauth until supplicant can properly deal
  // with RADIUS servers that respond strangely to such requests.
  // crbug.com/208561
  if (!supplicant_interface_proxy_->SetFastReauth(false)) {
    LOG(ERROR) << "Failed to disable fast_reauth. "
               << "May be running an older version of wpa_supplicant.";
  }

  // Helps with passing WiFiRoaming.001SSIDSwitchBack.
  if (!supplicant_interface_proxy_->SetScanInterval(kRescanIntervalSeconds)) {
    LOG(ERROR) << "Failed to set scan_interval. "
               << "May be running an older version of wpa_supplicant.";
  }

  if (random_mac_enabled_ &&
      !supplicant_interface_proxy_->EnableMacAddressRandomization(
          kRandomMacMask, sched_scan_supported_)) {
    LOG(ERROR) << "Failed to enable MAC address randomization. "
               << "May be running an older version of wpa_supplicant.";
  }

  // Remove all the credentials set in supplicant.
  if (!supplicant_interface_proxy_->RemoveAllCreds()) {
    LOG(ERROR) << "Failed to clear credentials from wpa_supplicant";
  }

  // Push our set of passpoint credentials.
  std::vector<PasspointCredentialsRefPtr> credentials =
      provider_->GetCredentials();
  for (const auto& c : credentials) {
    AddCred(c);
  }

  Scan(nullptr, __func__);
  StartScanTimer();
}

void WiFi::Restart() {
  LOG(INFO) << link_name() << " restarting.";
  WiFiRefPtr me = this;  // Make sure we don't get destructed.
  // Go through the manager rather than starting and stopping the device
  // directly so that the device can be configured with the profile.
  manager()->DeregisterDevice(me);
  manager()->RegisterDevice(me);
}

void WiFi::GetPhyInfo() {
  GetWiphyMessage get_wiphy;
  get_wiphy.AddFlag(NLM_F_DUMP);
  get_wiphy.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                               interface_index());
  get_wiphy.attributes()->SetFlagAttributeValue(NL80211_ATTR_SPLIT_WIPHY_DUMP,
                                                true);
  netlink_manager_->SendNl80211Message(
      &get_wiphy,
      base::Bind(&WiFi::OnNewWiphy,
                 weak_ptr_factory_while_started_.GetWeakPtr()),
      base::Bind(&NetlinkManager::OnAckDoNothing),
      base::Bind(&NetlinkManager::OnNetlinkMessageError));
}

void WiFi::OnNewWiphy(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_WIPHY.
  if (nl80211_message.command() != NewWiphyMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command:" << nl80211_message.command();
    return;
  }
  if (wake_on_wifi_) {
    wake_on_wifi_->ParseWakeOnWiFiCapabilities(nl80211_message);
  }
  // Parse and set wiphy_index_.
  bool wiphy_index_parsed = ParseWiphyIndex(nl80211_message);
  if (wiphy_index_parsed && wake_on_wifi_) {
    wake_on_wifi_->OnWiphyIndexReceived(wiphy_index_);
  }

  // Requires wiphy_index_.
  GetRegulatory();

  // This checks NL80211_ATTR_FEATURE_FLAGS.
  ParseFeatureFlags(nl80211_message);

  // The attributes, for this message, are complicated.
  // NL80211_ATTR_BANDS contains an array of bands...
  AttributeListConstRefPtr wiphy_bands;
  if (nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_WIPHY_BANDS, &wiphy_bands)) {
    AttributeIdIterator band_iter(*wiphy_bands);
    for (; !band_iter.AtEnd(); band_iter.Advance()) {
      AttributeListConstRefPtr wiphy_band;
      if (!wiphy_bands->ConstGetNestedAttributeList(band_iter.GetId(),
                                                    &wiphy_band)) {
        LOG(WARNING) << "WiFi band " << band_iter.GetId() << " not found";
        continue;
      }

      // ...Each band has a FREQS attribute...
      AttributeListConstRefPtr frequencies;
      if (!wiphy_band->ConstGetNestedAttributeList(NL80211_BAND_ATTR_FREQS,
                                                   &frequencies)) {
        continue;
      }

      // ...And each FREQS attribute contains an array of information about the
      // frequency...
      AttributeIdIterator freq_iter(*frequencies);
      for (; !freq_iter.AtEnd(); freq_iter.Advance()) {
        AttributeListConstRefPtr frequency;
        if (frequencies->ConstGetNestedAttributeList(freq_iter.GetId(),
                                                     &frequency)) {
          // ...Including the frequency, itself (the part we want).
          uint32_t frequency_value = 0;
          if (frequency->GetU32AttributeValue(NL80211_FREQUENCY_ATTR_FREQ,
                                              &frequency_value)) {
            SLOG(this, 7) << "Found frequency[" << freq_iter.GetId()
                          << "] = " << frequency_value;
            all_scan_frequencies_.insert(frequency_value);
          }
        }
      }
    }
  }
}

void WiFi::GetRegulatory() {
  GetRegMessage reg_msg;
  if (wiphy_index_ != kDefaultWiphyIndex) {
    reg_msg.attributes()->SetU32AttributeValue(NL80211_ATTR_WIPHY,
                                               wiphy_index_);
  }
  netlink_manager_->SendNl80211Message(
      &reg_msg,
      base::Bind(&WiFi::OnGetReg, weak_ptr_factory_while_started_.GetWeakPtr()),
      base::Bind(&NetlinkManager::OnAckDoNothing),
      base::Bind(&NetlinkManager::OnNetlinkMessageError));
}

void WiFi::OnTriggerPassiveScanResponse(const Nl80211Message& netlink_message) {
  LOG(WARNING) << "Didn't expect _this_netlink message ("
               << netlink_message.command() << " here:";
  netlink_message.Print(0, 0);
  return;
}

SupplicantProcessProxyInterface* WiFi::supplicant_process_proxy() const {
  return manager()->supplicant_manager()->proxy();
}

KeyValueStore WiFi::GetLinkStatistics(Error* /*error*/) {
  return link_statistics_;
}

Uint16s WiFi::GetAllScanFrequencies(Error* /* error */) {
  return {begin(all_scan_frequencies_), end(all_scan_frequencies_)};
}

bool WiFi::GetScanPending(Error* /* error */) {
  return scan_state_ == kScanScanning || scan_state_ == kScanBackgroundScanning;
}

bool WiFi::GetWakeOnWiFiSupported(Error* /* error */) {
  return wake_on_wifi_ != nullptr;
}

void WiFi::SetScanState(ScanState new_state,
                        ScanMethod new_method,
                        const char* reason) {
  if (new_state == kScanIdle)
    new_method = kScanMethodNone;
  if (new_state == kScanConnected) {
    // The scan method shouldn't be changed by the connection process, so
    // we'll put a CHECK, here, to verify.  NOTE: this assumption is also
    // enforced by the parameters to the call to |ReportScanResultToUma|.
    CHECK(new_method == scan_method_);
  }

  int log_level = 6;
  bool state_or_method_changed = true;
  bool is_terminal_state = false;
  if (new_state == scan_state_ && new_method == scan_method_) {
    log_level = 7;
    state_or_method_changed = false;
  } else if (new_state == kScanConnected || new_state == kScanFoundNothing) {
    // These 'terminal' states are slightly more interesting than the
    // intermediate states.
    // NOTE: Since background scan goes directly to kScanIdle (skipping over
    // the states required to set |is_terminal_state|), ReportScanResultToUma,
    // below, doesn't get called.  That's intentional.
    log_level = 5;
    is_terminal_state = true;
  }

  SLOG(this, log_level) << (reason ? reason : "<unknown>") << " - "
                        << link_name() << ": Scan state: "
                        << ScanStateString(scan_state_, scan_method_) << " -> "
                        << ScanStateString(new_state, new_method);
  if (!state_or_method_changed)
    return;

  // Actually change the state.
  ScanState old_state = scan_state_;
  ScanMethod old_method = scan_method_;
  bool old_scan_pending = GetScanPending(nullptr);
  scan_state_ = new_state;
  scan_method_ = new_method;
  bool new_scan_pending = GetScanPending(nullptr);
  if (old_scan_pending != new_scan_pending) {
    adaptor()->EmitBoolChanged(kScanningProperty, new_scan_pending);
  }
  switch (new_state) {
    case kScanIdle:
      metrics()->ResetScanTimer(interface_index());
      metrics()->ResetConnectTimer(interface_index());
      HandleEnsuredScan(old_state);
      break;
    case kScanScanning:  // FALLTHROUGH
    case kScanBackgroundScanning:
      if (new_state != old_state) {
        metrics()->NotifyDeviceScanStarted(interface_index());
      }
      break;
    case kScanConnecting:
      metrics()->NotifyDeviceScanFinished(interface_index());
      metrics()->NotifyDeviceConnectStarted(interface_index());
      break;
    case kScanConnected:
      metrics()->NotifyDeviceConnectFinished(interface_index());
      break;
    case kScanFoundNothing:
      // Note that finishing a scan that hasn't started (if, for example, we
      // get here when we fail to complete a connection) does nothing.
      metrics()->NotifyDeviceScanFinished(interface_index());
      metrics()->ResetConnectTimer(interface_index());
      break;
    case kScanTransitionToConnecting:  // FALLTHROUGH
    default:
      break;
  }
  if (is_terminal_state) {
    ReportScanResultToUma(new_state, old_method);
    // Now that we've logged a terminal state, let's call ourselves to
    // transition to the idle state.
    SetScanState(kScanIdle, kScanMethodNone, reason);
  }
}

void WiFi::HandleEnsuredScan(ScanState old_scan_state) {
  switch (ensured_scan_state_) {
    case EnsuredScanState::kWaiting:
      ensured_scan_state_ = EnsuredScanState::kScanning;
      // This starts a scan in the event loop, allowing SetScanState
      // to complete before proceeding.
      Scan(nullptr, "Previous scan complete. Starting ensured scan.");
      break;
    case EnsuredScanState::kScanning:
      // If the last state was a scanning-related state, the scan actually
      // executed.  Otherwise there was a race condition for the radio, and
      // a new scan should be started.
      switch (old_scan_state) {
        case kScanScanning:
        case kScanBackgroundScanning:
        case kScanFoundNothing:
          ensured_scan_state_ = EnsuredScanState::kIdle;
          // This connects to best services in the event loop, allowing
          // SetScanState to complete before proceeding.
          manager()->ConnectToBestServices(nullptr);
          break;
        case kScanTransitionToConnecting:
        case kScanConnecting:
        case kScanConnected:
        case kScanIdle:
          // This starts a scan in the event loop, allowing SetScanState
          // to complete before proceeding.
          Scan(nullptr, "Ensured scan didn't occur. Requesting another scan.");
          break;
      }
      break;
    case EnsuredScanState::kIdle:
      break;
  }
}

// static
std::string WiFi::ScanStateString(ScanState state, ScanMethod method) {
  switch (state) {
    case kScanIdle:
      return "IDLE";
    case kScanScanning:
      DCHECK(method != kScanMethodNone) << "Scanning with no scan method.";
      switch (method) {
        case kScanMethodFull:
          return "FULL_START";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    case kScanBackgroundScanning:
      return "BACKGROUND_START";
    case kScanTransitionToConnecting:
      return "TRANSITION_TO_CONNECTING";
    case kScanConnecting:
      switch (method) {
        case kScanMethodNone:
          return "CONNECTING (not scan related)";
        case kScanMethodFull:
          return "FULL_CONNECTING";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    case kScanConnected:
      switch (method) {
        case kScanMethodNone:
          return "CONNECTED (not scan related; e.g., from a supplicant roam)";
        case kScanMethodFull:
          return "FULL_CONNECTED";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    case kScanFoundNothing:
      switch (method) {
        case kScanMethodNone:
          return "CONNECT FAILED (not scan related)";
        case kScanMethodFull:
          return "FULL_NOCONNECTION";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    default:
      NOTREACHED();
  }
  return "";  // To shut up the compiler (that doesn't understand NOTREACHED).
}

void WiFi::ReportScanResultToUma(ScanState state, ScanMethod method) {
  Metrics::WiFiScanResult result = Metrics::kScanResultMax;
  if (state == kScanConnected) {
    switch (method) {
      case kScanMethodFull:
        result = Metrics::kScanResultFullScanConnected;
        break;
      default:
        // OK: Connect resulting from something other than scan.
        break;
    }
  } else if (state == kScanFoundNothing) {
    switch (method) {
      case kScanMethodFull:
        result = Metrics::kScanResultFullScanFoundNothing;
        break;
      default:
        // OK: Connect failed, not scan related.
        break;
    }
  }

  if (result != Metrics::kScanResultMax) {
    metrics()->SendEnumToUMA(Metrics::kMetricScanResult, result,
                             Metrics::kScanResultMax);
  }
}

void WiFi::RequestStationInfo() {
  if (!IsConnectedToCurrentService()) {
    LOG(ERROR) << "Not collecting station info because we are not connected.";
    return;
  }

  EndpointMap::iterator endpoint_it = endpoint_by_rpcid_.find(supplicant_bss_);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    LOG(ERROR) << "Can't get endpoint for current supplicant BSS "
               << supplicant_bss_.value();
    return;
  }

  GetStationMessage get_station;
  if (!get_station.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                                      interface_index())) {
    LOG(ERROR) << "Could not add IFINDEX attribute for GetStation message.";
    return;
  }

  const WiFiEndpointConstRefPtr endpoint(endpoint_it->second);
  if (!get_station.attributes()->SetRawAttributeValue(
          NL80211_ATTR_MAC,
          ByteString::CreateFromHexString(endpoint->bssid_hex()))) {
    LOG(ERROR) << "Could not add MAC attribute for GetStation message.";
    return;
  }

  netlink_manager_->SendNl80211Message(
      &get_station,
      base::Bind(&WiFi::OnReceivedStationInfo,
                 weak_ptr_factory_while_started_.GetWeakPtr()),
      base::Bind(&NetlinkManager::OnAckDoNothing),
      base::Bind(&NetlinkManager::OnNetlinkMessageError));

  request_station_info_callback_.Reset(base::Bind(
      &WiFi::RequestStationInfo, weak_ptr_factory_while_started_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(FROM_HERE,
                                request_station_info_callback_.callback(),
                                kRequestStationInfoPeriod);
}

// static
bool WiFi::ParseStationBitrate(const AttributeListConstRefPtr& rate_info,
                               std::string* out,
                               int* rate_out) {
  uint32_t rate = 0;      // In 100Kbps.
  uint16_t u16_rate = 0;  // In 100Kbps.
  uint8_t mcs = 0;
  uint8_t nss = 0;
  bool band_flag = false;
  bool is_short_gi = false;
  std::string mcs_info;
  std::string nss_info;
  std::string band_info;

  if (rate_info->GetU16AttributeValue(NL80211_RATE_INFO_BITRATE, &u16_rate)) {
    rate = static_cast<uint32_t>(u16_rate);
  } else {
    rate_info->GetU32AttributeValue(NL80211_RATE_INFO_BITRATE32, &rate);
  }

  if (rate_info->GetU8AttributeValue(NL80211_RATE_INFO_MCS, &mcs)) {
    mcs_info = base::StringPrintf(" MCS %d", mcs);
  } else if (rate_info->GetU8AttributeValue(NL80211_RATE_INFO_VHT_MCS, &mcs)) {
    mcs_info = base::StringPrintf(" VHT-MCS %d", mcs);
  }

  if (rate_info->GetU8AttributeValue(NL80211_RATE_INFO_VHT_NSS, &nss)) {
    nss_info = base::StringPrintf(" VHT-NSS %d", nss);
  }

  if (rate_info->GetFlagAttributeValue(NL80211_RATE_INFO_40_MHZ_WIDTH,
                                       &band_flag) &&
      band_flag) {
    band_info = base::StringPrintf(" 40MHz");
  } else if (rate_info->GetFlagAttributeValue(NL80211_RATE_INFO_80_MHZ_WIDTH,
                                              &band_flag) &&
             band_flag) {
    band_info = base::StringPrintf(" 80MHz");
  } else if (rate_info->GetFlagAttributeValue(NL80211_RATE_INFO_80P80_MHZ_WIDTH,
                                              &band_flag) &&
             band_flag) {
    band_info = base::StringPrintf(" 80+80MHz");
  } else if (rate_info->GetFlagAttributeValue(NL80211_RATE_INFO_160_MHZ_WIDTH,
                                              &band_flag) &&
             band_flag) {
    band_info = base::StringPrintf(" 160MHz");
  }

  rate_info->GetFlagAttributeValue(NL80211_RATE_INFO_SHORT_GI, &is_short_gi);

  if (rate) {
    *out = base::StringPrintf("%d.%d MBit/s%s%s%s%s", rate / 10, rate % 10,
                              mcs_info.c_str(), band_info.c_str(),
                              is_short_gi ? " short GI" : "", nss_info.c_str());
    *rate_out = rate / 10;
    return true;
  }

  return false;
}

void WiFi::OnReceivedStationInfo(const Nl80211Message& nl80211_message) {
  // Verify NL80211_CMD_NEW_STATION
  if (nl80211_message.command() != NewStationMessage::kCommand) {
    LOG(ERROR) << "Received unexpected command:" << nl80211_message.command();
    return;
  }

  if (!IsConnectedToCurrentService()) {
    LOG(ERROR) << "Not accepting station info because we are not connected.";
    return;
  }

  EndpointMap::iterator endpoint_it = endpoint_by_rpcid_.find(supplicant_bss_);
  if (endpoint_it == endpoint_by_rpcid_.end()) {
    LOG(ERROR) << "Can't get endpoint for current supplicant BSS."
               << supplicant_bss_.value();
    return;
  }

  ByteString station_bssid;
  if (!nl80211_message.const_attributes()->GetRawAttributeValue(
          NL80211_ATTR_MAC, &station_bssid)) {
    LOG(ERROR) << "Unable to get MAC attribute from received station info.";
    return;
  }

  WiFiEndpointRefPtr endpoint(endpoint_it->second);

  if (!station_bssid.Equals(
          ByteString::CreateFromHexString(endpoint->bssid_hex()))) {
    LOG(ERROR) << "Received station info for a non-current BSS.";
    return;
  }

  AttributeListConstRefPtr station_info;
  if (!nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_STA_INFO, &station_info)) {
    LOG(ERROR) << "Received station info had no NL80211_ATTR_STA_INFO.";
    return;
  }

  uint8_t signal;
  if (!station_info->GetU8AttributeValue(NL80211_STA_INFO_SIGNAL, &signal)) {
    LOG(ERROR) << "Received station info had no NL80211_STA_INFO_SIGNAL.";
    return;
  }

  endpoint->UpdateSignalStrength(static_cast<signed char>(signal));

  link_statistics_.Clear();

  std::map<int, std::string> u32_property_map = {
      {NL80211_STA_INFO_INACTIVE_TIME, kInactiveTimeMillisecondsProperty},
      {NL80211_STA_INFO_RX_PACKETS, kPacketReceiveSuccessesProperty},
      {NL80211_STA_INFO_TX_FAILED, kPacketTransmitFailuresProperty},
      {NL80211_STA_INFO_TX_PACKETS, kPacketTransmitSuccessesProperty},
      {NL80211_STA_INFO_TX_RETRIES, kTransmitRetriesProperty}};

  for (const auto& kv : u32_property_map) {
    uint32_t value;
    if (station_info->GetU32AttributeValue(kv.first, &value)) {
      link_statistics_.Set<uint32_t>(kv.second, value);
    }
  }

  std::map<int, std::string> s8_property_map = {
      {NL80211_STA_INFO_SIGNAL, kLastReceiveSignalDbmProperty},
      {NL80211_STA_INFO_SIGNAL_AVG, kAverageReceiveSignalDbmProperty}};

  for (const auto& kv : s8_property_map) {
    uint8_t value;
    if (station_info->GetU8AttributeValue(kv.first, &value)) {
      // Despite these values being reported as a U8 by the kernel, these
      // should be interpreted as signed char.
      link_statistics_.Set<int32_t>(kv.second, static_cast<signed char>(value));
    }
  }

  AttributeListConstRefPtr transmit_info;
  if (station_info->ConstGetNestedAttributeList(NL80211_STA_INFO_TX_BITRATE,
                                                &transmit_info)) {
    std::string str;
    int rate;
    if (ParseStationBitrate(transmit_info, &str, &rate)) {
      link_statistics_.Set<std::string>(kTransmitBitrateProperty, str);
      metrics()->NotifyWifiTxBitrate(rate);
    }
  }

  AttributeListConstRefPtr receive_info;
  if (station_info->ConstGetNestedAttributeList(NL80211_STA_INFO_RX_BITRATE,
                                                &receive_info)) {
    std::string str;
    int rate;
    if (ParseStationBitrate(receive_info, &str, &rate)) {
      link_statistics_.Set<std::string>(kReceiveBitrateProperty, str);
    }
  }
}

void WiFi::StopRequestingStationInfo() {
  SLOG(this, 2) << "WiFi Device " << link_name() << ": " << __func__;
  request_station_info_callback_.Cancel();
  link_statistics_.Clear();
}

void WiFi::RemoveSupplicantNetworks() {
  for (const auto& map_entry : rpcid_by_service_) {
    RemoveNetwork(map_entry.second);
  }
  rpcid_by_service_.clear();
}

void WiFi::OnGetDHCPLease() {
  if (!wake_on_wifi_) {
    return;
  }
  SLOG(this, 3) << __func__ << ": "
                << "IPv4 DHCP lease obtained";
  wake_on_wifi_->OnConnectedAndReachable(TimeToNextDHCPLeaseRenewal());
}

void WiFi::OnGetSLAACAddress() {
  if (!IsConnectedToCurrentService()) {
    return;
  }
  if (!wake_on_wifi_) {
    return;
  }
  SLOG(this, 3) << __func__ << ": "
                << "IPv6 configuration obtained through SLAAC";
  wake_on_wifi_->OnConnectedAndReachable(std::nullopt);
}

bool WiFi::IsConnectedToCurrentService() {
  return (current_service_ && current_service_->IsConnected());
}

void WiFi::ReportConnectedToServiceAfterWake() {
  int seconds_in_suspend = (manager()->GetSuspendDurationUsecs() / 1000000);
  if (wake_on_wifi_) {
    wake_on_wifi_->ReportConnectedToServiceAfterWake(
        IsConnectedToCurrentService(), seconds_in_suspend);
  }
}

bool WiFi::RequestRoam(const std::string& addr, Error* error) {
  if (!supplicant_interface_proxy_->Roam(addr)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf("%s: requested roam to %s failed",
                           link_name().c_str(), addr.c_str()));
    return false;
  }
  return true;
}

// TODO(b/184395063): determine this at runtime.
bool WiFi::SupportsWPA3() const {
#if !defined(DISABLE_WPA3_SAE)
  return true;
#else
  return false;
#endif
}

void WiFi::GetDeviceHardwareIds(int* vendor,
                                int* product,
                                int* subsystem) const {
  if (manager() && manager()->device_info()) {
    manager()->device_info()->GetWiFiHardwareIds(interface_index(), vendor,
                                                 product, subsystem);
  }
}

void WiFi::OnNeighborReachabilityEvent(
    const IPAddress& ip_address,
    patchpanel::NeighborReachabilityEventSignal::Role role,
    patchpanel::NeighborReachabilityEventSignal::EventType event_type) {
  using EventSignal = patchpanel::NeighborReachabilityEventSignal;

  if (event_type == EventSignal::FAILED) {
    metrics()->NotifyNeighborLinkMonitorFailure(Technology::kWiFi,
                                                ip_address.family(), role);
  }

  if (!selected_service()) {
    LOG(INFO)
        << "Device " << link_name()
        << ": Ignored neighbor reachability event due to no selected service";
    return;
  }
  if (selected_service()->link_monitor_disabled()) {
    SLOG(this, 2) << "Device " << link_name()
                  << ": Link Monitoring is disabled for the selected service";
    return;
  }

  // Checks if the signal is for the gateway of the current connection.
  if (role == EventSignal::DNS_SERVER) {
    return;
  }
  if (!connection()) {
    SLOG(this, 2) << "Device " << link_name()
                  << ": No active connection. Skipped.";
    return;
  }
  if (!(ipconfig() &&
        ip_address.ToString() == ipconfig()->properties().gateway) &&
      !(ip6config() &&
        ip_address.ToString() == ip6config()->properties().gateway)) {
    LOG(INFO) << "Device " << link_name()
              << ": Ignored neighbor reachability event since gateway address "
                 "does not match.";
    return;
  }

  switch (event_type) {
    case EventSignal::REACHABLE:
      if (ip_address.family() == IPAddress::kFamilyIPv4) {
        ipv4_gateway_found_ = true;
      } else if (ip_address.family() == IPAddress::kFamilyIPv6) {
        ipv6_gateway_found_ = true;
      } else {
        NOTREACHED();
      }
      return;
    case EventSignal::FAILED:
      OnLinkMonitorFailure(ip_address.family());
      return;
    default:
      // Already filtered in DeviceInfo::OnPatchpanelClientReady().
      NOTREACHED();
  }
}

uint64_t WiFi::GetReceiveByteCount() {
  uint64_t rx_byte_count = 0, tx_byte_count = 0;
  manager()->device_info()->GetByteCounts(interface_index(), &rx_byte_count,
                                          &tx_byte_count);
  return rx_byte_count;
}

}  // namespace shill
