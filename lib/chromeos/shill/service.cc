// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/service.h"

#include <stdio.h>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

//#include <base/check.h>
//#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>

#include "shill/connection.h"
#include "shill/dbus/dbus_control.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/event_history.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
#include "shill/eap_credentials.h"
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

namespace shill {

namespace {
const char kServiceSortAutoConnect[] = "AutoConnect";
const char kServiceSortConnectable[] = "Connectable";
const char kServiceSortHasEverConnected[] = "HasEverConnected";
const char kServiceSortManagedCredentials[] = "ManagedCredentials";
const char kServiceSortIsConnected[] = "IsConnected";
const char kServiceSortIsConnecting[] = "IsConnecting";
const char kServiceSortIsFailed[] = "IsFailed";
const char kServiceSortIsOnline[] = "IsOnline";
const char kServiceSortIsPortalled[] = "IsPortal";
const char kServiceSortPriority[] = "Priority";
const char kServiceSortSecurity[] = "Security";
const char kServiceSortSource[] = "Source";
const char kServiceSortProfileOrder[] = "ProfileOrder";
const char kServiceSortEtc[] = "Etc";
const char kServiceSortSerialNumber[] = "SerialNumber";
const char kServiceSortTechnology[] = "Technology";
const char kServiceSortTechnologySpecific[] = "TechnologySpecific";

std::valarray<uint64_t> CounterToValArray(
    const patchpanel::TrafficCounter& counter) {
  return std::valarray<uint64_t>{counter.rx_bytes(), counter.tx_bytes(),
                                 counter.rx_packets(), counter.tx_packets()};
}

// Extracts enum value but with enum's underlying type.
// This is a part of c++23, but it's quite useful even now.
template <typename T>
static constexpr auto toUnderlying(T val) {
  return static_cast<std::underlying_type_t<T>>(val);
}

// This is the mapping of ONC enum values and their textual representation.
static constexpr std::array<const char*,
                            toUnderlying(Service::ONCSource::kONCSourcesNum)>
    ONCSourceMapping = {kONCSourceUnknown, kONCSourceNone, kONCSourceUserImport,
                        kONCSourceDevicePolicy, kONCSourceUserPolicy};

}  // namespace

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kService;
static std::string ObjectID(const Service* s) {
  return s->log_name();
}
}  // namespace Logging

const char Service::kAutoConnBusy[] = "busy";
const char Service::kAutoConnConnected[] = "connected";
const char Service::kAutoConnConnecting[] = "connecting";
const char Service::kAutoConnDisconnecting[] = "disconnecting";
const char Service::kAutoConnExplicitDisconnect[] = "explicitly disconnected";
const char Service::kAutoConnNotConnectable[] = "not connectable";
const char Service::kAutoConnOffline[] = "offline";
const char Service::kAutoConnTechnologyNotAutoConnectable[] =
    "technology not auto connectable";
const char Service::kAutoConnThrottled[] = "throttled";
const char Service::kAutoConnMediumUnavailable[] =
    "connection medium unavailable";
const char Service::kAutoConnRecentBadPassphraseFailure[] =
    "recent bad passphrase failure";

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
const size_t Service::kEAPMaxCertificationElements = 10;
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

const char Service::kCheckPortalAuto[] = "auto";
const char Service::kCheckPortalFalse[] = "false";
const char Service::kCheckPortalTrue[] = "true";

const char Service::kErrorDetailsNone[] = "";

const int Service::kPriorityNone = 0;

const char Service::kStorageAutoConnect[] = "AutoConnect";
const char Service::kStorageCheckPortal[] = "CheckPortal";
const char Service::kStorageError[] = "Error";
const char Service::kStorageGUID[] = "GUID";
const char Service::kStorageHasEverConnected[] = "HasEverConnected";
const char Service::kStorageName[] = "Name";
const char Service::kStoragePriority[] = "Priority";
const char Service::kStorageProxyConfig[] = "ProxyConfig";
const char Service::kStorageSaveCredentials[] = "SaveCredentials";
const char Service::kStorageType[] = "Type";
const char Service::kStorageUIData[] = "UIData";
const char Service::kStorageONCSource[] = "ONCSource";
const char Service::kStorageConnectionId[] = "ConnectionId";
const char Service::kStorageLinkMonitorDisabled[] = "LinkMonitorDisabled";
const char Service::kStorageManagedCredentials[] = "ManagedCredentials";
const char Service::kStorageMeteredOverride[] = "MeteredOverride";
const char Service::kStorageCurrentTrafficCounterPrefix[] =
    "TrafficCounterCurrent";
const char Service::kStorageTrafficCounterRxBytesSuffix[] = "RxBytes";
const char Service::kStorageTrafficCounterTxBytesSuffix[] = "TxBytes";
const char Service::kStorageTrafficCounterRxPacketsSuffix[] = "RxPackets";
const char Service::kStorageTrafficCounterTxPacketsSuffix[] = "TxPackets";
const char* const Service::kStorageTrafficCounterSuffixes[] = {
    kStorageTrafficCounterRxBytesSuffix, kStorageTrafficCounterTxBytesSuffix,
    kStorageTrafficCounterRxPacketsSuffix,
    kStorageTrafficCounterTxPacketsSuffix};
const char Service::kStorageTrafficCounterResetTime[] =
    "TrafficCounterResetTime";

const size_t Service::kTrafficCounterArraySize = 4;

const uint8_t Service::kStrengthMax = 100;
const uint8_t Service::kStrengthMin = 0;

const base::TimeDelta Service::kMinAutoConnectCooldownTime = base::Seconds(1);
const base::TimeDelta Service::kMaxAutoConnectCooldownTime = base::Minutes(1);
const uint64_t Service::kAutoConnectCooldownBackoffFactor = 2;

// TODO(b/184036481): convert all of these to base::TimeDelta
const int Service::kDisconnectsMonitorSeconds = 5 * 60;
const int Service::kMisconnectsMonitorSeconds = 5 * 60;
const int Service::kMaxDisconnectEventHistory = 20;
const int Service::kMaxMisconnectEventHistory = 20;

// static
unsigned int Service::next_serial_number_ = 0;

Service::Service(Manager* manager, Technology technology)
    : weak_ptr_factory_(this),
      state_(kStateIdle),
      previous_state_(kStateIdle),
      failure_(kFailureNone),
      auto_connect_(false),
      retain_auto_connect_(false),
      was_visible_(false),
      check_portal_(kCheckPortalAuto),
      connectable_(false),
      error_(ConnectFailureToString(failure_)),
      error_details_(kErrorDetailsNone),
      previous_error_serial_number_(0),
      explicitly_disconnected_(false),
      is_in_user_connect_(false),
      priority_(kPriorityNone),
      crypto_algorithm_(kCryptoNone),
      key_rotation_(false),
      endpoint_auth_(false),
      portal_detection_failure_status_code_(0),
      strength_(0),
      save_credentials_(true),
      technology_(technology),
      has_ever_connected_(false),
      disconnects_(kMaxDisconnectEventHistory),
      misconnects_(kMaxMisconnectEventHistory),
      store_(PropertyStore::PropertyChangeCallback(base::Bind(
          &Service::OnPropertyChanged, weak_ptr_factory_.GetWeakPtr()))),
      serial_number_(next_serial_number_++),
      adaptor_(manager->control_interface()->CreateServiceAdaptor(this)),
      manager_(manager),
      link_monitor_disabled_(false),
      managed_credentials_(false),
      unreliable_(false),
      source_(ONCSource::kONCSourceUnknown) {
  // Provide a default name.
  friendly_name_ = "service_" + base::NumberToString(serial_number_);
  log_name_ = friendly_name_;

  HelpRegisterDerivedBool(kAutoConnectProperty, &Service::GetAutoConnect,
                          &Service::SetAutoConnectFull,
                          &Service::ClearAutoConnect);

  // kActivationTypeProperty: Registered in CellularService
  // kActivationStateProperty: Registered in CellularService
  // kCellularApnProperty: Registered in CellularService
  // kCellularLastGoodApnProperty: Registered in CellularService
  // kNetworkTechnologyProperty: Registered in CellularService
  // kOutOfCreditsProperty: Registered in CellularService
  // kPaymentPortalProperty: Registered in CellularService
  // kRoamingStateProperty: Registered in CellularService
  // kServingOperatorProperty: Registered in CellularService
  // kUsageURLProperty: Registered in CellularService
  // kCellularPPPUsernameProperty: Registered in CellularService
  // kCellularPPPPasswordProperty: Registered in CellularService

  HelpRegisterDerivedString(kCheckPortalProperty, &Service::GetCheckPortal,
                            &Service::SetCheckPortal);
  store_.RegisterConstBool(kConnectableProperty, &connectable_);
  HelpRegisterConstDerivedRpcIdentifier(kDeviceProperty,
                                        &Service::GetDeviceRpcId);
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  store_.RegisterConstStrings(kEapRemoteCertificationProperty,
                              &remote_certification_);
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X
  HelpRegisterDerivedString(kGuidProperty, &Service::GetGuid,
                            &Service::SetGuid);

  // TODO(ers): in flimflam clearing Error has the side-effect of
  // setting the service state to IDLE. Is this important? I could
  // see an autotest depending on it.
  store_.RegisterConstString(kErrorProperty, &error_);
  store_.RegisterConstString(kErrorDetailsProperty, &error_details_);
  HelpRegisterConstDerivedRpcIdentifier(kIPConfigProperty,
                                        &Service::GetIPConfigRpcIdentifier);
  store_.RegisterDerivedBool(
      kIsConnectedProperty,
      BoolAccessor(new CustomReadOnlyAccessor<Service, bool>(
          this, &Service::IsConnected)));
  // kModeProperty: Registered in WiFiService

  HelpRegisterDerivedString(kNameProperty, &Service::GetNameProperty,
                            &Service::SetNameProperty);
  // kPassphraseProperty: Registered in WiFiService
  // kPassphraseRequiredProperty: Registered in WiFiService
  store_.RegisterConstString(kPreviousErrorProperty, &previous_error_);
  store_.RegisterConstInt32(kPreviousErrorSerialNumberProperty,
                            &previous_error_serial_number_);
  HelpRegisterDerivedInt32(kPriorityProperty, &Service::GetPriority,
                           &Service::SetPriority);
  HelpRegisterDerivedString(kProfileProperty, &Service::GetProfileRpcId,
                            &Service::SetProfileRpcId);
  HelpRegisterDerivedString(kProxyConfigProperty, &Service::GetProxyConfig,
                            &Service::SetProxyConfig);
  store_.RegisterBool(kSaveCredentialsProperty, &save_credentials_);
  HelpRegisterDerivedString(kTypeProperty, &Service::CalculateTechnology,
                            nullptr);
  // kSecurityProperty: Registered in WiFiService
  HelpRegisterDerivedString(kStateProperty, &Service::CalculateState, nullptr);
  store_.RegisterConstUint8(kSignalStrengthProperty, &strength_);
  store_.RegisterString(kUIDataProperty, &ui_data_);
  HelpRegisterConstDerivedStrings(kDiagnosticsDisconnectsProperty,
                                  &Service::GetDisconnectsProperty);
  HelpRegisterConstDerivedStrings(kDiagnosticsMisconnectsProperty,
                                  &Service::GetMisconnectsProperty);
  store_.RegisterBool(kLinkMonitorDisableProperty, &link_monitor_disabled_);
  store_.RegisterBool(kManagedCredentialsProperty, &managed_credentials_);
  HelpRegisterDerivedBool(kMeteredProperty, &Service::GetMeteredProperty,
                          &Service::SetMeteredProperty,
                          &Service::ClearMeteredProperty);

  HelpRegisterDerivedBool(kVisibleProperty, &Service::GetVisibleProperty,
                          nullptr, nullptr);

  store_.RegisterConstString(kProbeUrlProperty, &probe_url_string_);
  store_.RegisterConstString(kPortalDetectionFailedPhaseProperty,
                             &portal_detection_failure_phase_);
  store_.RegisterConstString(kPortalDetectionFailedStatusProperty,
                             &portal_detection_failure_status_);
  store_.RegisterConstInt32(kPortalDetectionFailedStatusCodeProperty,
                            &portal_detection_failure_status_code_);

  HelpRegisterDerivedString(kONCSourceProperty, &Service::GetONCSource,
                            &Service::SetONCSource);
  HelpRegisterConstDerivedUint64(kTrafficCounterResetTimeProperty,
                                 &Service::GetTrafficCounterResetTimeProperty);

  metrics()->RegisterService(*this);

  static_ip_parameters_.PlumbPropertyStore(&store_);

  IgnoreParameterForConfigure(kTypeProperty);
  IgnoreParameterForConfigure(kProfileProperty);

  SLOG(this, 1) << technology << " Service " << serial_number_
                << " constructed.";
}

Service::~Service() {
  metrics()->DeregisterService(*this);
  SLOG(this, 1) << technology() << " Service " << serial_number_
                << " destroyed.";
}

void Service::AutoConnect() {
  const char* reason = nullptr;
  if (!IsAutoConnectable(&reason)) {
    if (reason == kAutoConnTechnologyNotAutoConnectable ||
        reason == kAutoConnConnected) {
      SLOG(this, 3) << "Suppressed autoconnect to " << log_name()
                    << " Reason: " << reason;
    } else if (reason == kAutoConnBusy ||
               reason == kAutoConnMediumUnavailable) {
      SLOG(this, 1) << "Suppressed autoconnect to " << log_name()
                    << " Reason: " << reason;
    } else {
      LOG(INFO) << "Suppressed autoconnect to " << log_name()
                << " Reason: " << reason;
    }
    return;
  }

  Error error;
  LOG(INFO) << "Auto-connecting to " << log_name();
  ThrottleFutureAutoConnects();
  Connect(&error, __func__);
}

void Service::Connect(Error* error, const char* reason) {
  CHECK(reason);
  if (!connectable()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf(
            "Connect attempted but %s Service %s is not connectable: %s",
            technology().GetName().c_str(), log_name().c_str(), reason));
    return;
  }

  if (IsConnected()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kAlreadyConnected,
        base::StringPrintf(
            "Connect attempted but %s Service %s is already connected: %s",
            technology().GetName().c_str(), log_name().c_str(), reason));
    return;
  }
  if (IsConnecting()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInProgress,
        base::StringPrintf(
            "Connect attempted but %s Service %s already connecting: %s",
            technology().GetName().c_str(), log_name().c_str(), reason));
    return;
  }
  if (IsDisconnecting()) {
    // SetState will re-trigger a connection after this disconnection has
    // completed.
    pending_connect_task_.Reset(
        base::Bind(&Service::Connect, weak_ptr_factory_.GetWeakPtr(),
                   base::Owned(new Error()), "Triggering delayed Connect"));
    return;
  }

  pending_connect_task_.Cancel();
  // This cannot be called until here because |explicitly_disconnected_| is
  // used in determining whether or not this Service can be AutoConnected.
  ClearExplicitlyDisconnected();

  // Note: this log is parsed by logprocessor.
  LOG(INFO) << "Connecting to " << technology() << " Service " << log_name()
            << ": " << reason;

  // Clear any failure state from a previous connect attempt.
  if (IsInFailState())
    SetState(kStateIdle);

  // Perform connection logic defined by children. This logic will
  // drive the state from kStateIdle.
  OnConnect(error);
}

void Service::Disconnect(Error* error, const char* reason) {
  CHECK(reason);
  if (!IsDisconnectable(error)) {
    LOG(WARNING) << "Disconnect attempted but " << log_name()
                 << " is not Disconnectable"
                 << ": " << reason;
    return;
  }

  LOG(INFO) << "Disconnecting from " << log_name() << ": " << reason;
  SetState(kStateDisconnecting);
  // Perform connection logic defined by children. This logic will
  // drive the state to kStateIdle.
  OnDisconnect(error, reason);
}

void Service::DisconnectWithFailure(ConnectFailure failure,
                                    Error* error,
                                    const char* reason) {
  SLOG(this, 1) << __func__ << ": " << ConnectFailureToString(failure);
  CHECK(reason);
  Disconnect(error, reason);
  SetFailure(failure);
}

void Service::UserInitiatedConnect(const char* reason, Error* error) {
  Connect(error, reason);

  // Since Service::Connect will clear a failure state when it gets far enough,
  // we know that |error| not indicating an failure but this instance being in a
  // failure state means that a Device drove the state to failure. We do this
  // because Ethernet and WiFi currently don't have |error| passed down to
  // ConnectTo.
  //
  // TODO(crbug.com/206812) Pipe |error| through to WiFi and Ethernet ConnectTo.
  if (error->IsFailure() || IsInFailState()) {
    if (connectable() && error->type() != Error::kAlreadyConnected &&
        error->type() != Error::kInProgress) {
      ReportUserInitiatedConnectionResult(state());
    }
    // If we've already failed, SetState will not be able to catch this failure
    // before |is_in_user_connect_| is set (in fact the state may not even
    // change by the time the failure occurs). Setting |is_in_user_connect_| in
    // this case will act as setting either the next or already-ongoing Connect
    // as being user-initiated, even if it isn't.
    return;
  }
  is_in_user_connect_ = true;
}

void Service::UserInitiatedDisconnect(const char* reason, Error* error) {
  // |explicitly_disconnected_| should be set prior to calling Disconnect, as
  // Disconnect flows could otherwise potentially hit NoteFailureEvent prior to
  // this being set.
  explicitly_disconnected_ = true;
  Disconnect(error, reason);
}

void Service::CompleteCellularActivation(Error* error) {
  Error::PopulateAndLog(FROM_HERE, error, Error::kNotImplemented,
                        "Service doesn't support cellular activation "
                        "completion for technology: " +
                            GetTechnologyString());
}

std::string Service::GetWiFiPassphrase(Error* error) {
  Error::PopulateAndLog(FROM_HERE, error, Error::kNotImplemented,
                        "Service doesn't support WiFi passphrase retrieval for "
                        "technology: " +
                            GetTechnologyString());
  return std::string();
}

bool Service::IsActive(Error* /*error*/) const {
  return state() != kStateUnknown && state() != kStateIdle &&
         state() != kStateFailure && state() != kStateDisconnecting;
}

// static
bool Service::IsConnectedState(ConnectState state) {
  return (state == kStateConnected || IsPortalledState(state) ||
          state == kStateOnline);
}

// static
bool Service::IsConnectingState(ConnectState state) {
  return (state == kStateAssociating || state == kStateConfiguring);
}

// static
bool Service::IsPortalledState(ConnectState state) {
  return state == kStateNoConnectivity || state == kStateRedirectFound ||
         state == kStatePortalSuspected;
}

bool Service::IsConnected(Error* /*error*/) const {
  return IsConnectedState(state());
}

bool Service::IsConnecting() const {
  return IsConnectingState(state());
}

bool Service::IsDisconnecting() const {
  return state() == kStateDisconnecting;
}

bool Service::IsPortalled() const {
  return IsPortalledState(state());
}

bool Service::IsFailed() const {
  // We sometimes lie about the failure state, to keep Chrome happy
  // (see comment in WiFi::HandleDisconnect). Hence, we check both
  // state and |failed_time_|.
  return state() == kStateFailure || !failed_time_.is_null();
}

bool Service::IsInFailState() const {
  return state() == kStateFailure;
}

bool Service::IsOnline() const {
  return state() == kStateOnline;
}

void Service::SetState(ConnectState state) {
  if (state == state_) {
    return;
  }

  // Note: this log is parsed by logprocessor.
  LOG(INFO) << "Service " << log_name() << ": state "
            << ConnectStateToString(state_) << " -> "
            << ConnectStateToString(state);

  if (!pending_connect_task_.IsCancelled() &&
      (state == kStateFailure || state == kStateIdle)) {
    dispatcher()->PostTask(FROM_HERE, pending_connect_task_.callback());
  }

  // Metric reporting for result of user-initiated connection attempt.
  if (is_in_user_connect_ &&
      ((state == kStateConnected) || (state == kStateFailure) ||
       (state == kStateIdle))) {
    ReportUserInitiatedConnectionResult(state);
    is_in_user_connect_ = false;
  }

  if (state == kStateFailure) {
    NoteFailureEvent();
  }

  previous_state_ = state_;
  state_ = state;
  if (state != kStateFailure) {
    failure_ = kFailureNone;
    SetErrorDetails(kErrorDetailsNone);
  }
  if (state == kStateConnected) {
    failed_time_ = base::Time();
    has_ever_connected_ = true;
    SaveToProfile();
    // When we succeed in connecting, forget that connects failed in the past.
    // Give services one chance at a fast autoconnect retry by resetting the
    // cooldown to 0 to indicate that the last connect was successful.
    auto_connect_cooldown_ = base::TimeDelta();
    reenable_auto_connect_task_.Cancel();
  }
  UpdateErrorProperty();
  manager_->NotifyServiceStateChanged(this);
  metrics()->NotifyServiceStateChanged(*this, state);

  if (IsConnectedState(previous_state_) != IsConnectedState(state_)) {
    adaptor_->EmitBoolChanged(kIsConnectedProperty, IsConnected());
  }
  adaptor_->EmitStringChanged(kStateProperty, GetStateString());
}

void Service::SetPortalDetectionFailure(const std::string& phase,
                                        const std::string& status,
                                        int status_code) {
  if (portal_detection_failure_phase_ != phase) {
    portal_detection_failure_phase_ = phase;
    adaptor_->EmitStringChanged(kPortalDetectionFailedPhaseProperty, phase);
  }
  if (portal_detection_failure_status_ != status) {
    portal_detection_failure_status_ = status;
    adaptor_->EmitStringChanged(kPortalDetectionFailedStatusProperty, status);
  }
  if (portal_detection_failure_status_code_ != status_code) {
    portal_detection_failure_status_code_ = status_code;
    adaptor_->EmitIntChanged(kPortalDetectionFailedStatusCodeProperty,
                             status_code);
  }
}

void Service::SetProbeUrl(const std::string& probe_url_string) {
  if (probe_url_string_ == probe_url_string) {
    return;
  }
  probe_url_string_ = probe_url_string;
  adaptor_->EmitStringChanged(kProbeUrlProperty, probe_url_string);
}

void Service::ReEnableAutoConnectTask() {
  // Kill the thing blocking AutoConnect().
  reenable_auto_connect_task_.Cancel();
  // Post to the manager, giving it an opportunity to AutoConnect again.
  manager_->UpdateService(this);
}

void Service::ThrottleFutureAutoConnects() {
  if (!auto_connect_cooldown_.is_zero()) {
    LOG(INFO) << "Throttling future autoconnects to " << log_name()
              << ". Next autoconnect in " << auto_connect_cooldown_;
    reenable_auto_connect_task_.Reset(base::Bind(
        &Service::ReEnableAutoConnectTask, weak_ptr_factory_.GetWeakPtr()));
    dispatcher()->PostDelayedTask(FROM_HERE,
                                  reenable_auto_connect_task_.callback(),
                                  auto_connect_cooldown_);
  }
  auto min_cooldown_time =
      std::max(kMinAutoConnectCooldownTime,
               auto_connect_cooldown_ * kAutoConnectCooldownBackoffFactor);
  auto_connect_cooldown_ =
      std::min(GetMaxAutoConnectCooldownTime(), min_cooldown_time);
}

void Service::SaveFailure() {
  previous_error_ = ConnectFailureToString(failure_);
  ++previous_error_serial_number_;
}

void Service::SetFailure(ConnectFailure failure) {
  SLOG(this, 1) << __func__ << ": " << ConnectFailureToString(failure);
  failure_ = failure;
  failed_time_ = base::Time::Now();
  SaveFailure();
  UpdateErrorProperty();
  SetState(kStateFailure);
}

void Service::SetFailureSilent(ConnectFailure failure) {
  SLOG(this, 1) << __func__ << ": " << ConnectFailureToString(failure);
  NoteFailureEvent();
  // Note that order matters here, since SetState modifies |failure_| and
  // |failed_time_|.
  SetState(kStateIdle);
  failure_ = failure;
  failed_time_ = base::Time::Now();
  SaveFailure();
  UpdateErrorProperty();
}

std::optional<base::TimeDelta> Service::GetTimeSinceFailed() const {
  if (failed_time_.is_null())
    return std::nullopt;
  return base::Time::Now() - failed_time_;
}

std::string Service::GetDBusObjectPathIdentifer() const {
  return base::NumberToString(serial_number());
}

const RpcIdentifier& Service::GetRpcIdentifier() const {
  return adaptor_->GetRpcIdentifier();
}

std::string Service::GetLoadableStorageIdentifier(
    const StoreInterface& storage) const {
  return IsLoadableFrom(storage) ? GetStorageIdentifier() : "";
}

bool Service::IsLoadableFrom(const StoreInterface& storage) const {
  return storage.ContainsGroup(GetStorageIdentifier());
}

Service::ONCSource Service::ParseONCSourceFromUIData() {
  // If ONC Source was not stored directly, we may still guess it
  // from ONC Data blob.
  if (ui_data_.find("\"onc_source\":\"device_policy\"") != std::string::npos) {
    return ONCSource::kONCSourceDevicePolicy;
  }
  if (ui_data_.find("\"onc_source\":\"user_policy\"") != std::string::npos) {
    return ONCSource::kONCSourceUserPolicy;
  }
  if (ui_data_.find("\"onc_source\":\"user_import\"") != std::string::npos) {
    return ONCSource::kONCSourceUserImport;
  }
  return ONCSource::kONCSourceUnknown;
}

bool Service::Load(const StoreInterface* storage) {
  const auto id = GetStorageIdentifier();
  if (!storage->ContainsGroup(id)) {
    LOG(WARNING) << "Service is not available in the persistent store: " << id;
    return false;
  }

  auto_connect_ = IsAutoConnectByDefault();
  retain_auto_connect_ =
      storage->GetBool(id, kStorageAutoConnect, &auto_connect_);

  LoadString(storage, id, kStorageCheckPortal, kCheckPortalAuto,
             &check_portal_);
  LoadString(storage, id, kStorageGUID, "", &guid_);
  if (!storage->GetInt(id, kStoragePriority, &priority_)) {
    priority_ = kPriorityNone;
  }
  LoadString(storage, id, kStorageProxyConfig, "", &proxy_config_);
  storage->GetBool(id, kStorageSaveCredentials, &save_credentials_);
  LoadString(storage, id, kStorageUIData, "", &ui_data_);

  // Check if service comes from a managed policy.
  int source;
  auto ret = storage->GetInt(id, kStorageONCSource, &source);
  if (!ret || (source > static_cast<int>(ONCSource::kONCSourceUserPolicy))) {
    source_ = ONCSource::kONCSourceUnknown;
  } else {
    source_ = static_cast<ONCSource>(source);
  }
  SLOG(this, 2) << " Service source = " << static_cast<size_t>(source_);

  storage->GetBool(id, kStorageLinkMonitorDisabled, &link_monitor_disabled_);
  if (!storage->GetBool(id, kStorageManagedCredentials,
                        &managed_credentials_)) {
    managed_credentials_ = false;
  }

  bool metered_override;
  if (storage->GetBool(id, kStorageMeteredOverride, &metered_override)) {
    metered_override_ = metered_override;
  }

  // Note that service might be connected when Load() is called, e.g., Ethernet
  // service will keep connected when profile is changed.
  if (static_ip_parameters_.Load(storage, id)) {
    NotifyStaticIPConfigChanged();
  }

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  // Call OnEapCredentialsChanged with kReasonCredentialsLoaded to avoid
  // resetting the has_ever_connected value.
  if (mutable_eap()) {
    mutable_eap()->Load(storage, id);
    OnEapCredentialsChanged(kReasonCredentialsLoaded);
  }
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

  ClearExplicitlyDisconnected();

  // Read has_ever_connected_ value from stored profile
  // now that the credentials have been loaded.
  storage->GetBool(id, kStorageHasEverConnected, &has_ever_connected_);

  for (patchpanel::TrafficCounter::Source source =
           patchpanel::TrafficCounter::Source_MIN;
       source <= patchpanel::TrafficCounter::Source_MAX;
       source = patchpanel::TrafficCounter::Source(source + 1)) {
    std::valarray<uint64_t> counter_array(kTrafficCounterArraySize);
    for (size_t i = 0; i < kTrafficCounterArraySize; i++) {
      storage->GetUint64(id,
                         GetCurrentTrafficCounterKey(
                             source, kStorageTrafficCounterSuffixes[i]),
                         &counter_array[i]);
    }
    if (counter_array.sum()) {
      current_traffic_counters_[source] = counter_array;
    } else {
      current_traffic_counters_.erase(source);
    }
  }

  uint64_t traffic_counter_reset_time_ms;
  if (storage->GetUint64(id, kStorageTrafficCounterResetTime,
                         &traffic_counter_reset_time_ms)) {
    traffic_counter_reset_time_ = base::Time::FromDeltaSinceWindowsEpoch(
        base::Milliseconds(traffic_counter_reset_time_ms));
  }

  return true;
}

void Service::MigrateDeprecatedStorage(StoreInterface* storage) {
  const auto id = GetStorageIdentifier();
  CHECK(storage->ContainsGroup(id));

  // Deprecated key removed in M91 by patch with Change-Id
  // Ic45f1fff097a1e54e0d762cacb3d2bdf7d8f5341
  // TODO(b/182744859): Remove code after M93.
  storage->DeleteKey(id, "DNSAutoFallback");

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  if (eap()) {
    eap()->MigrateDeprecatedStorage(storage, id);
  }
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

  // Prior to M91, Chrome did not tell us the source directly. We derive it
  // from UIData for old services. Remove this migration code in M97+.
  if (source_ == ONCSource::kONCSourceUnknown) {
    source_ = ParseONCSourceFromUIData();
    storage->SetInt(id, kStorageONCSource, toUnderlying(source_));
  }

  // This property is deprecated in M92 in crrev.com/c/2814180. Remove this
  // migration code in M94+.
  storage->DeleteKey(id, kStorageConnectionId);
}

bool Service::Unload() {
  auto_connect_ = IsAutoConnectByDefault();
  retain_auto_connect_ = false;
  check_portal_ = kCheckPortalAuto;
  ClearExplicitlyDisconnected();
  guid_ = "";
  has_ever_connected_ = false;
  priority_ = kPriorityNone;
  proxy_config_ = "";
  save_credentials_ = true;
  ui_data_ = "";
  link_monitor_disabled_ = false;
  managed_credentials_ = false;
  source_ = ONCSource::kONCSourceUnknown;
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  if (mutable_eap()) {
    mutable_eap()->Reset();
  }
  ClearEAPCertification();
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X
  if (IsActive(nullptr)) {
    Error error;  // Ignored.
    Disconnect(&error, __func__);
  }
  current_traffic_counters_.clear();
  static_ip_parameters_.Reset();
  return false;
}

void Service::Remove(Error* /*error*/) {
  manager()->RemoveService(this);
  // |this| may no longer be valid now.
}

bool Service::Save(StoreInterface* storage) {
  const auto id = GetStorageIdentifier();

  storage->SetString(id, kStorageType, GetTechnologyString());

  // IMPORTANT: Changes to kStorageAutoConnect must be backwards compatible, see
  // WiFiService::Save for details.
  if (retain_auto_connect_) {
    storage->SetBool(id, kStorageAutoConnect, auto_connect_);
  } else {
    storage->DeleteKey(id, kStorageAutoConnect);
  }

  if (check_portal_ == kCheckPortalAuto) {
    storage->DeleteKey(id, kStorageCheckPortal);
  } else {
    storage->SetString(id, kStorageCheckPortal, check_portal_);
  }

  SaveStringOrClear(storage, id, kStorageGUID, guid_);
  storage->SetBool(id, kStorageHasEverConnected, has_ever_connected_);
  storage->SetString(id, kStorageName, friendly_name_);
  if (priority_ != kPriorityNone) {
    storage->SetInt(id, kStoragePriority, priority_);
  } else {
    storage->DeleteKey(id, kStoragePriority);
  }
  SaveStringOrClear(storage, id, kStorageProxyConfig, proxy_config_);
  storage->SetBool(id, kStorageSaveCredentials, save_credentials_);
  SaveStringOrClear(storage, id, kStorageUIData, ui_data_);
  storage->SetInt(id, kStorageONCSource, static_cast<int>(source_));
  storage->SetBool(id, kStorageLinkMonitorDisabled, link_monitor_disabled_);
  storage->SetBool(id, kStorageManagedCredentials, managed_credentials_);

  if (metered_override_.has_value()) {
    storage->SetBool(id, kStorageMeteredOverride, metered_override_.value());
  } else {
    storage->DeleteKey(id, kStorageMeteredOverride);
  }

  static_ip_parameters_.Save(storage, id);
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  if (eap()) {
    eap()->Save(storage, id, save_credentials_);
  }
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

  for (patchpanel::TrafficCounter::Source source =
           patchpanel::TrafficCounter::Source_MIN;
       source < patchpanel::TrafficCounter::Source_MAX;
       source = patchpanel::TrafficCounter::Source(source + 1)) {
    bool in_storage = current_traffic_counters_.find(source) !=
                      current_traffic_counters_.end();
    for (size_t i = 0; i < kTrafficCounterArraySize; i++) {
      std::string key = GetCurrentTrafficCounterKey(
          source, kStorageTrafficCounterSuffixes[i]);
      if (in_storage) {
        storage->SetUint64(id, key, current_traffic_counters_[source][i]);
      } else {
        storage->DeleteKey(id, key);
      }
    }
  }

  storage->SetUint64(id, kStorageTrafficCounterResetTime,
                     GetTrafficCounterResetTimeProperty(/*error=*/nullptr));

  return true;
}

void Service::Configure(const KeyValueStore& args, Error* error) {
  for (const auto& it : args.properties()) {
    if (it.second.IsTypeCompatible<bool>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring bool property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring bool property: " << it.first;
      Error set_error;
      store_.SetBoolProperty(it.first, it.second.Get<bool>(), &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    } else if (it.second.IsTypeCompatible<int32_t>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring int32_t property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring int32_t property: " << it.first;
      Error set_error;
      store_.SetInt32Property(it.first, it.second.Get<int32_t>(), &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    } else if (it.second.IsTypeCompatible<KeyValueStore>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring key value store property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring key value store property: " << it.first;
      Error set_error;
      store_.SetKeyValueStoreProperty(it.first, it.second.Get<KeyValueStore>(),
                                      &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    } else if (it.second.IsTypeCompatible<std::string>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring string property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring string property: " << it.first;
      Error set_error;
      store_.SetStringProperty(it.first, it.second.Get<std::string>(),
                               &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    } else if (it.second.IsTypeCompatible<Strings>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring strings property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring strings property: " << it.first;
      Error set_error;
      store_.SetStringsProperty(it.first, it.second.Get<Strings>(), &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    } else if (it.second.IsTypeCompatible<Stringmap>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring stringmap property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring stringmap property: " << it.first;
      Error set_error;
      store_.SetStringmapProperty(it.first, it.second.Get<Stringmap>(),
                                  &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    } else if (it.second.IsTypeCompatible<Stringmaps>()) {
      if (base::Contains(parameters_ignored_for_configure_, it.first)) {
        SLOG(this, 5) << "Ignoring stringmaps property: " << it.first;
        continue;
      }
      SLOG(this, 5) << "Configuring stringmaps property: " << it.first;
      Error set_error;
      store_.SetStringmapsProperty(it.first, it.second.Get<Stringmaps>(),
                                   &set_error);
      if (error->IsSuccess() && set_error.IsFailure()) {
        error->CopyFrom(set_error);
      }
    }
  }
}

bool Service::DoPropertiesMatch(const KeyValueStore& args) const {
  for (const auto& it : args.properties()) {
    if (it.second.IsTypeCompatible<bool>()) {
      SLOG(this, 5) << "Checking bool property: " << it.first;
      Error get_error;
      bool value;
      if (!store_.GetBoolProperty(it.first, &value, &get_error) ||
          value != it.second.Get<bool>()) {
        return false;
      }
    } else if (it.second.IsTypeCompatible<int32_t>()) {
      SLOG(this, 5) << "Checking int32 property: " << it.first;
      Error get_error;
      int32_t value;
      if (!store_.GetInt32Property(it.first, &value, &get_error) ||
          value != it.second.Get<int32_t>()) {
        return false;
      }
    } else if (it.second.IsTypeCompatible<std::string>()) {
      SLOG(this, 5) << "Checking string property: " << it.first;
      Error get_error;
      std::string value;
      if (!store_.GetStringProperty(it.first, &value, &get_error) ||
          value != it.second.Get<std::string>()) {
        return false;
      }
    } else if (it.second.IsTypeCompatible<Strings>()) {
      SLOG(this, 5) << "Checking strings property: " << it.first;
      Error get_error;
      Strings value;
      if (!store_.GetStringsProperty(it.first, &value, &get_error) ||
          value != it.second.Get<Strings>()) {
        return false;
      }
    } else if (it.second.IsTypeCompatible<Stringmap>()) {
      SLOG(this, 5) << "Checking stringmap property: " << it.first;
      Error get_error;
      Stringmap value;
      if (!store_.GetStringmapProperty(it.first, &value, &get_error) ||
          value != it.second.Get<Stringmap>()) {
        return false;
      }
    } else if (it.second.IsTypeCompatible<KeyValueStore>()) {
      SLOG(this, 5) << "Checking key value store property: " << it.first;
      Error get_error;
      KeyValueStore value;
      if (!store_.GetKeyValueStoreProperty(it.first, &value, &get_error) ||
          value != it.second.Get<KeyValueStore>()) {
        return false;
      }
    }
  }
  return true;
}

bool Service::IsRemembered() const {
  return profile_ && !manager_->IsServiceEphemeral(this);
}

void Service::EnableAndRetainAutoConnect() {
  if (retain_auto_connect_) {
    // We do not want to clobber the value of auto_connect_ (it may
    // be user-set). So return early.
    return;
  }

  SetAutoConnect(true);
  RetainAutoConnect();
}

void Service::SetIPConfig(
    RpcIdentifier ipconfig_rpc_id,
    base::RepeatingClosure static_ipconfig_changed_callback) {
  if (ipconfig_rpc_id.value().empty()) {
    static_ip_parameters_.ClearSavedParameters();
  }
  ipconfig_rpc_identifier_ = ipconfig_rpc_id;
  static_ipconfig_changed_callback_ = static_ipconfig_changed_callback;

  Error error;
  RpcIdentifier ipconfig = GetIPConfigRpcIdentifier(&error);
  if (error.IsSuccess()) {
    adaptor_->EmitRpcIdentifierChanged(kIPConfigProperty, ipconfig);
  }
}

bool Service::HasActiveConnection() const {
  return !ipconfig_rpc_identifier_.value().empty();
}

void Service::NotifyStaticIPConfigChanged() {
  if (!static_ipconfig_changed_callback_.is_null()) {
    static_ipconfig_changed_callback_.Run();
  }
}

VirtualDeviceRefPtr Service::GetVirtualDevice() const {
  return nullptr;
}

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
bool Service::Is8021xConnectable() const {
  return eap() && eap()->IsConnectable();
}

bool Service::AddEAPCertification(const std::string& name, size_t depth) {
  if (depth >= kEAPMaxCertificationElements) {
    LOG(WARNING) << "Ignoring certification " << name << " because depth "
                 << depth << " exceeds our maximum of "
                 << kEAPMaxCertificationElements;
    return false;
  }

  if (depth >= remote_certification_.size()) {
    remote_certification_.resize(depth + 1);
  } else if (name == remote_certification_[depth]) {
    return true;
  }

  remote_certification_[depth] = name;
  LOG(INFO) << "Received certification for " << name << " at depth " << depth;
  return true;
}

void Service::ClearEAPCertification() {
  remote_certification_.clear();
}

void Service::SetEapCredentials(EapCredentials* eap) {
  // This operation must be done at most once for the lifetime of the service.
  CHECK(eap && !eap_);

  eap_.reset(eap);
  eap_->InitPropertyStore(mutable_store());
}
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

std::string Service::GetEapPassphrase(Error* error) {
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  if (eap()) {
    return eap()->GetEapPassword(error);
  }
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X
  Error::PopulateAndLog(FROM_HERE, error, Error::kIllegalOperation,
                        "Cannot retrieve EAP passphrase from non-EAP network.");
  return std::string();
}

bool Service::HasStaticIPAddress() const {
  return static_ip_parameters().ContainsAddress();
}

bool Service::HasStaticNameServers() const {
  return static_ip_parameters().ContainsNameServers();
}

void Service::SetAutoConnect(bool connect) {
  if (auto_connect() == connect) {
    return;
  }
  LOG(INFO) << "Service " << log_name() << ": SetAutoConnect: " << connect;
  auto_connect_ = connect;
  adaptor_->EmitBoolChanged(kAutoConnectProperty, auto_connect());
}

// static
// Note: keep in sync with ERROR_* constants in
// android/system/connectivity/shill/IService.aidl.
const char* Service::ConnectFailureToString(const ConnectFailure& state) {
  switch (state) {
    case kFailureNone:
      return kErrorNoFailure;
    case kFailureAAA:
      return kErrorAaaFailed;
    case kFailureActivation:
      return kErrorActivationFailed;
    case kFailureBadPassphrase:
      return kErrorBadPassphrase;
    case kFailureBadWEPKey:
      return kErrorBadWEPKey;
    case kFailureConnect:
      return kErrorConnectFailed;
    case kFailureDNSLookup:
      return kErrorDNSLookupFailed;
    case kFailureDHCP:
      return kErrorDhcpFailed;
    case kFailureEAPAuthentication:
      return kErrorEapAuthenticationFailed;
    case kFailureEAPLocalTLS:
      return kErrorEapLocalTlsFailed;
    case kFailureEAPRemoteTLS:
      return kErrorEapRemoteTlsFailed;
    case kFailureHTTPGet:
      return kErrorHTTPGetFailed;
    case kFailureInternal:
      return kErrorInternal;
    case kFailureIPsecCertAuth:
      return kErrorIpsecCertAuthFailed;
    case kFailureIPsecPSKAuth:
      return kErrorIpsecPskAuthFailed;
    case kFailureNeedEVDO:
      return kErrorNeedEvdo;
    case kFailureNeedHomeNetwork:
      return kErrorNeedHomeNetwork;
    case kFailureOTASP:
      return kErrorOtaspFailed;
    case kFailureOutOfRange:
      return kErrorOutOfRange;
    case kFailurePinMissing:
      return kErrorPinMissing;
    case kFailurePPPAuth:
      return kErrorPppAuthFailed;
    case kFailureSimLocked:
      return kErrorSimLocked;
    case kFailureNotRegistered:
      return kErrorNotRegistered;
    case kFailureUnknown:
      return kErrorUnknownFailure;
    case kFailureNotAssociated:
      return kErrorNotAssociated;
    case kFailureNotAuthenticated:
      return kErrorNotAuthenticated;
    case kFailureTooManySTAs:
      return kErrorTooManySTAs;
    case kFailureDisconnect:
      return kErrorDisconnect;
    case kFailureMax:
      NOTREACHED();
  }
  return "Invalid";
}

// static
const char* Service::ConnectStateToString(const ConnectState& state) {
  switch (state) {
    case kStateUnknown:
      return "Unknown";
    case kStateIdle:
      return "Idle";
    case kStateAssociating:
      return "Associating";
    case kStateConfiguring:
      return "Configuring";
    case kStateConnected:
      return "Connected";
    case kStateNoConnectivity:
      return "No connectivity";
    case kStateRedirectFound:
      return "Redirect found";
    case kStatePortalSuspected:
      return "Portal suspected";
    case kStateFailure:
      return "Failure";
    case kStateOnline:
      return "Online";
    case kStateDisconnecting:
      return "Disconnecting";
  }
  return "Invalid";
}

std::string Service::GetTechnologyString() const {
  return technology().GetName();
}

bool Service::ShouldIgnoreFailure() const {
  // Ignore the event if it's user-initiated explicit disconnect.
  if (explicitly_disconnected_) {
    SLOG(this, 2) << "Explicit disconnect ignored.";
    return true;
  }
  // Ignore the event if manager is not running (e.g., service disconnects on
  // shutdown).
  if (!manager_->running()) {
    SLOG(this, 2) << "Disconnect while manager stopped ignored.";
    return true;
  }
  // Ignore the event if the system is suspending.
  // TODO(b/179949996): This is racy because the failure event isn't guaranteed
  // to come before PowerManager::OnSuspendDone().
  PowerManager* power_manager = manager_->power_manager();
  if (!power_manager || power_manager->suspending()) {
    SLOG(this, 2) << "Disconnect in transitional power state ignored.";
    return true;
  }
  return false;
}

void Service::NoteFailureEvent() {
  SLOG(this, 2) << __func__;
  if (ShouldIgnoreFailure()) {
    return;
  }
  int period = 0;
  EventHistory* events = nullptr;
  // Sometimes services transition to Idle before going into a failed state so
  // take into account the last non-idle state.
  ConnectState state = state_ == kStateIdle ? previous_state_ : state_;
  if (IsConnectedState(state)) {
    LOG(INFO) << "Noting an unexpected connection drop.";
    period = kDisconnectsMonitorSeconds;
    events = &disconnects_;
  } else if (IsConnectingState(state)) {
    LOG(INFO) << "Noting an unexpected failure to connect.";
    period = kMisconnectsMonitorSeconds;
    events = &misconnects_;
  } else {
    SLOG(this, 2) << "Not connected or connecting, state transition ignored.";
    return;
  }
  events->RecordEventAndExpireEventsBefore(period,
                                           EventHistory::kClockTypeMonotonic);
}

void Service::ReportUserInitiatedConnectionResult(ConnectState state) {
  // Report stats for wifi only for now.
  if (technology_ != Technology::kWiFi)
    return;

  int result;
  switch (state) {
    case kStateConnected:
      result = Metrics::kUserInitiatedConnectionResultSuccess;
      break;
    case kStateFailure:
      result = Metrics::kUserInitiatedConnectionResultFailure;
      metrics()->NotifyUserInitiatedConnectionFailureReason(
          Metrics::kMetricWifiUserInitiatedConnectionFailureReason, failure_);
      break;
    case kStateIdle:
      // This assumes the device specific class (wifi, cellular) will advance
      // the service's state from idle to other state after connection attempt
      // is initiated for the given service.
      result = Metrics::kUserInitiatedConnectionResultAborted;
      break;
    default:
      return;
  }

  metrics()->NotifyUserInitiatedConnectionResult(
      Metrics::kMetricWifiUserInitiatedConnectionResult, result);
}

bool Service::HasRecentConnectionIssues() {
  disconnects_.ExpireEventsBefore(kDisconnectsMonitorSeconds,
                                  EventHistory::kClockTypeMonotonic);
  misconnects_.ExpireEventsBefore(kMisconnectsMonitorSeconds,
                                  EventHistory::kClockTypeMonotonic);
  return !disconnects_.Empty() || !misconnects_.Empty();
}

// static
bool Service::DecideBetween(int a, int b, bool* decision) {
  if (a == b)
    return false;
  *decision = (a > b);
  return true;
}

uint16_t Service::SecurityLevel() {
  return (crypto_algorithm_ << 2) | (key_rotation_ << 1) | endpoint_auth_;
}

bool Service::IsMetered() const {
  if (metered_override_.has_value()) {
    return metered_override_.value();
  }

  if (IsMeteredByServiceProperties()) {
    return true;
  }

  TetheringState tethering = GetTethering();
  return tethering == TetheringState::kSuspected ||
         tethering == TetheringState::kConfirmed;
}

bool Service::IsMeteredByServiceProperties() const {
  return false;
}

void Service::InitializeTrafficCounterSnapshot(
    const std::vector<patchpanel::TrafficCounter>& counters) {
  for (const auto& counter : counters) {
    traffic_counter_snapshot_[counter.source()] = CounterToValArray(counter);
  }
}

void Service::RefreshTrafficCounters(
    const std::vector<patchpanel::TrafficCounter>& counters) {
  for (const auto& counter : counters) {
    std::valarray<uint64_t> counter_array = CounterToValArray(counter);
    if (current_traffic_counters_.find(counter.source()) ==
        current_traffic_counters_.end()) {
      current_traffic_counters_[counter.source()] =
          std::valarray<uint64_t>(kTrafficCounterArraySize);
    }
    if (traffic_counter_snapshot_[counter.source()].size() ==
        kTrafficCounterArraySize) {
      current_traffic_counters_[counter.source()] +=
          counter_array - traffic_counter_snapshot_[counter.source()];
    } else {
      LOG(WARNING) << "Uninitialized traffic counter snapshot for source "
                   << patchpanel::TrafficCounter::Source_Name(counter.source());
    }
    traffic_counter_snapshot_[counter.source()] = counter_array;
  }
  SaveToProfile();
}

void Service::RequestTrafficCountersCallback(
    Error* error,
    const ResultVariantDictionariesCallback& callback,
    const std::vector<patchpanel::TrafficCounter>& counters) {
  RefreshTrafficCounters(counters);
  std::vector<brillo::VariantDictionary> traffic_counters;
  for (const auto& [source, counters] : current_traffic_counters_) {
    brillo::VariantDictionary dict;
    // Select only the first two |counters| elements, corresponding to rx_bytes
    // and tx_bytes.
    dict.emplace("source", patchpanel::TrafficCounter::Source_Name(source));
    dict.emplace("rx_bytes", counters[TrafficCounterVals::kRxBytes]);
    dict.emplace("tx_bytes", counters[TrafficCounterVals::kTxBytes]);
    traffic_counters.push_back(std::move(dict));
  }
  error->Populate(Error::kSuccess);
  callback.Run(*error, std::move(traffic_counters));
}

void Service::RequestTrafficCounters(
    Error* error, const ResultVariantDictionariesCallback& callback) {
  DeviceRefPtr device = manager_->FindDeviceFromService(this);
  if (!device) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        "Failed to find device from service: " + GetRpcIdentifier().value());
    return;
  }
  std::set<std::string> devices{device->link_name()};
  patchpanel::Client* client = manager_->patchpanel_client();
  if (!client) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                          "Failed to get patchpanel client");
    return;
  }
  client->GetTrafficCounters(
      devices, BindOnce(&Service::RequestTrafficCountersCallback,
                        weak_ptr_factory_.GetWeakPtr(), error, callback));
}

void Service::ResetTrafficCounters(Error* /*error*/) {
  current_traffic_counters_.clear();
  traffic_counter_reset_time_ = base::Time::Now();
  SaveToProfile();
}

bool Service::CompareWithSameTechnology(const ServiceRefPtr& service,
                                        bool* decision) {
  return false;
}

// static
std::string Service::GetCurrentTrafficCounterKey(
    patchpanel::TrafficCounter::Source source, std::string suffix) {
  return std::string(kStorageCurrentTrafficCounterPrefix) +
         patchpanel::TrafficCounter::Source_Name(source) + suffix;
}

// static
std::pair<bool, const char*> Service::Compare(
    ServiceRefPtr a,
    ServiceRefPtr b,
    bool compare_connectivity_state,
    const std::vector<Technology>& tech_order) {
  CHECK_EQ(a->manager(), b->manager());
  bool ret;

  if (compare_connectivity_state && a->state() != b->state()) {
    if (DecideBetween(a->IsOnline(), b->IsOnline(), &ret)) {
      return std::make_pair(ret, kServiceSortIsOnline);
    }

    if (DecideBetween(a->IsConnected(), b->IsConnected(), &ret)) {
      return std::make_pair(ret, kServiceSortIsConnected);
    }

    if (DecideBetween(!a->IsPortalled(), !b->IsPortalled(), &ret)) {
      return std::make_pair(ret, kServiceSortIsPortalled);
    }

    if (DecideBetween(a->IsConnecting(), b->IsConnecting(), &ret)) {
      return std::make_pair(ret, kServiceSortIsConnecting);
    }

    if (DecideBetween(!a->IsFailed(), !b->IsFailed(), &ret)) {
      return std::make_pair(ret, kServiceSortIsFailed);
    }
  }

  if (DecideBetween(a->connectable(), b->connectable(), &ret)) {
    return std::make_pair(ret, kServiceSortConnectable);
  }

  for (auto technology : tech_order) {
    if (DecideBetween(a->technology() == technology,
                      b->technology() == technology, &ret)) {
      return std::make_pair(ret, kServiceSortTechnology);
    }
  }

  if (DecideBetween(a->priority(), b->priority(), &ret)) {
    return std::make_pair(ret, kServiceSortPriority);
  }

  if (DecideBetween(a->SourcePriority(), b->SourcePriority(), &ret)) {
    return std::make_pair(ret, kServiceSortSource);
  }

  if (DecideBetween(a->managed_credentials_, b->managed_credentials_, &ret)) {
    return std::make_pair(ret, kServiceSortManagedCredentials);
  }

  if (DecideBetween(a->auto_connect(), b->auto_connect(), &ret)) {
    return std::make_pair(ret, kServiceSortAutoConnect);
  }

  if (DecideBetween(a->SecurityLevel(), b->SecurityLevel(), &ret)) {
    return std::make_pair(ret, kServiceSortSecurity);
  }

  // If the profiles for the two services are different,
  // we want to pick the highest priority one.  The
  // ephemeral profile is explicitly tested for since it is not
  // listed in the manager profiles_ list.
  if (a->profile() != b->profile()) {
    Manager* manager = a->manager();
    ret = manager->IsServiceEphemeral(b) ||
          (!manager->IsServiceEphemeral(a) &&
           manager->IsProfileBefore(b->profile(), a->profile()));
    return std::make_pair(ret, kServiceSortProfileOrder);
  }

  if (DecideBetween(a->has_ever_connected(), b->has_ever_connected(), &ret)) {
    return std::make_pair(ret, kServiceSortHasEverConnected);
  }

  if (a->CompareWithSameTechnology(b, &ret)) {
    return std::make_pair(ret, kServiceSortTechnologySpecific);
  }

  if (DecideBetween(a->strength(), b->strength(), &ret)) {
    return std::make_pair(ret, kServiceSortEtc);
  }

  ret = a->serial_number_ < b->serial_number_;
  return std::make_pair(ret, kServiceSortSerialNumber);
}

// static
std::string Service::SanitizeStorageIdentifier(std::string identifier) {
  std::replace_if(
      identifier.begin(), identifier.end(),
      [](unsigned char c) { return !std::isalnum(c); }, '_');
  return identifier;
}

const ProfileRefPtr& Service::profile() const {
  return profile_;
}

void Service::set_profile(const ProfileRefPtr& p) {
  profile_ = p;
}

void Service::SetProfile(const ProfileRefPtr& p) {
  SLOG(this, 2) << "SetProfile for " << log_name() << " from "
                << (profile_ ? profile_->GetFriendlyName() : "(none)") << " to "
                << (p ? p->GetFriendlyName() : "(none)") << ".";
  if (profile_ == p) {
    return;
  }
  profile_ = p;
  Error error;
  std::string profile_rpc_id = GetProfileRpcId(&error);
  if (!error.IsSuccess()) {
    return;
  }
  adaptor_->EmitStringChanged(kProfileProperty, profile_rpc_id);
}

void Service::OnPropertyChanged(const std::string& property) {
  SLOG(this, 1) << __func__ << " " << property;
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  if (Is8021x() && EapCredentials::IsEapAuthenticationProperty(property)) {
    OnEapCredentialsChanged(kReasonPropertyUpdate);
  }
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X
  SaveToProfile();
  if (!IsConnected()) {
    return;
  }

  if (property == kCheckPortalProperty || property == kProxyConfigProperty) {
    manager_->RecheckPortalOnService(this);
  } else if (property == kPriorityProperty ||
             property == kManagedCredentialsProperty) {
    // These properties affect the sorting order of Services. Note that this is
    // only necessary if there are multiple connected Services that would be
    // sorted differently by this change, so we can avoid doing this for
    // unconnected Services.
    manager_->SortServices();
  } else if (property == kStaticIPConfigProperty) {
    NotifyStaticIPConfigChanged();
  }
}

void Service::OnBeforeSuspend(const ResultCallback& callback) {
  // Nothing to be done in the general case, so immediately report success.
  callback.Run(Error(Error::kSuccess));
}

void Service::OnAfterResume() {
  // Forget old autoconnect failures across suspend/resume.
  auto_connect_cooldown_ = base::TimeDelta();
  reenable_auto_connect_task_.Cancel();
  // Forget if the user disconnected us, we might be able to connect now.
  ClearExplicitlyDisconnected();
}

void Service::OnDarkResume() {
  // Nothing to do in the general case.
}

void Service::OnDefaultServiceStateChanged(const ServiceRefPtr& parent) {
  // Nothing to do in the general case.
}

RpcIdentifier Service::GetIPConfigRpcIdentifier(Error* error) const {
  if (ipconfig_rpc_identifier_.value().empty()) {
    // Do not return an empty IPConfig.
    error->Populate(Error::kNotFound);
    return DBusControl::NullRpcIdentifier();
  }

  return ipconfig_rpc_identifier_;
}

void Service::SetConnectable(bool connectable) {
  if (connectable_ == connectable)
    return;
  connectable_ = connectable;
  adaptor_->EmitBoolChanged(kConnectableProperty, connectable_);
}

void Service::SetConnectableFull(bool connectable) {
  if (connectable_ == connectable) {
    return;
  }
  SetConnectable(connectable);
  if (manager_->HasService(this)) {
    manager_->UpdateService(this);
  }
}

std::string Service::GetStateString() const {
  // TODO(benchan): We may want to rename shill::kState* to avoid name clashing
  // with Service::kState*.
  switch (state()) {
    case kStateIdle:
      return shill::kStateIdle;
    case kStateAssociating:
      return shill::kStateAssociation;
    case kStateConfiguring:
      return shill::kStateConfiguration;
    case kStateConnected:
      return shill::kStateReady;
    case kStateFailure:
      return shill::kStateFailure;
    case kStateNoConnectivity:
      return shill::kStateNoConnectivity;
    case kStateRedirectFound:
      return shill::kStateRedirectFound;
    case kStatePortalSuspected:
      return shill::kStatePortalSuspected;
    case kStateOnline:
      return shill::kStateOnline;
    case kStateDisconnecting:
      return shill::kStateDisconnect;
    case kStateUnknown:
    default:
      return "";
  }
}

bool Service::IsAutoConnectable(const char** reason) const {
  if (manager_->IsTechnologyAutoConnectDisabled(technology_)) {
    *reason = kAutoConnTechnologyNotAutoConnectable;
    return false;
  }

  if (!connectable()) {
    *reason = kAutoConnNotConnectable;
    return false;
  }

  if (IsConnected()) {
    *reason = kAutoConnConnected;
    return false;
  }

  if (IsConnecting()) {
    *reason = kAutoConnConnecting;
    return false;
  }

  if (IsDisconnecting()) {
    *reason = kAutoConnDisconnecting;
    return false;
  }

  if (explicitly_disconnected_) {
    *reason = kAutoConnExplicitDisconnect;
    return false;
  }

  if (!reenable_auto_connect_task_.IsCancelled()) {
    *reason = kAutoConnThrottled;
    return false;
  }

  if (!technology_.IsPrimaryConnectivityTechnology() &&
      !manager_->IsConnected()) {
    *reason = kAutoConnOffline;
    return false;
  }

  // It's possible for a connection failure to trigger an autoconnect to the
  // same Service. This happens with no cooldown, so we'll see a connection
  // failure immediately followed by an autoconnect attempt. This is desirable
  // in many cases (e.g. there's a brief AP-/network-side issue), but not when
  // the failure is due to a bad passphrase. Enforce a minimum cooldown time to
  // avoid this.
  auto time_since_failed = GetTimeSinceFailed();
  if (time_since_failed &&
      time_since_failed.value() < kMinAutoConnectCooldownTime &&
      previous_error_ == kErrorBadPassphrase) {
    *reason = kAutoConnRecentBadPassphraseFailure;
    return false;
  }

  return true;
}

base::TimeDelta Service::GetMaxAutoConnectCooldownTime() const {
  return kMaxAutoConnectCooldownTime;
}

bool Service::IsDisconnectable(Error* error) const {
  if (!IsActive(nullptr)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kNotConnected,
        base::StringPrintf("Disconnect attempted but Service is not active: %s",
                           log_name().c_str()));
    return false;
  }
  return true;
}

bool Service::IsPortalDetectionDisabled() const {
  return check_portal_ == kCheckPortalFalse;
}

bool Service::IsPortalDetectionAuto() const {
  return check_portal_ == kCheckPortalAuto;
}

void Service::HelpRegisterDerivedBool(const std::string& name,
                                      bool (Service::*get)(Error* error),
                                      bool (Service::*set)(const bool&, Error*),
                                      void (Service::*clear)(Error*)) {
  store_.RegisterDerivedBool(
      name,
      BoolAccessor(new CustomAccessor<Service, bool>(this, get, set, clear)));
}

void Service::HelpRegisterDerivedInt32(const std::string& name,
                                       int32_t (Service::*get)(Error* error),
                                       bool (Service::*set)(const int32_t&,
                                                            Error*)) {
  store_.RegisterDerivedInt32(
      name,
      Int32Accessor(new CustomAccessor<Service, int32_t>(this, get, set)));
}

void Service::HelpRegisterDerivedString(
    const std::string& name,
    std::string (Service::*get)(Error* error),
    bool (Service::*set)(const std::string&, Error*)) {
  store_.RegisterDerivedString(
      name,
      StringAccessor(new CustomAccessor<Service, std::string>(this, get, set)));
}

void Service::HelpRegisterConstDerivedRpcIdentifier(
    const std::string& name, RpcIdentifier (Service::*get)(Error*) const) {
  store_.RegisterDerivedRpcIdentifier(
      name, RpcIdentifierAccessor(
                new CustomReadOnlyAccessor<Service, RpcIdentifier>(this, get)));
}

void Service::HelpRegisterConstDerivedStrings(
    const std::string& name, Strings (Service::*get)(Error* error) const) {
  store_.RegisterDerivedStrings(
      name,
      StringsAccessor(new CustomReadOnlyAccessor<Service, Strings>(this, get)));
}

void Service::HelpRegisterConstDerivedString(
    const std::string& name, std::string (Service::*get)(Error* error) const) {
  store_.RegisterDerivedString(
      name, StringAccessor(
                new CustomReadOnlyAccessor<Service, std::string>(this, get)));
}

void Service::HelpRegisterConstDerivedUint64(
    const std::string& name, uint64_t (Service::*get)(Error* error) const) {
  store_.RegisterDerivedUint64(
      name,
      Uint64Accessor(new CustomReadOnlyAccessor<Service, uint64_t>(this, get)));
}

// static
void Service::LoadString(const StoreInterface* storage,
                         const std::string& id,
                         const std::string& key,
                         const std::string& default_value,
                         std::string* value) {
  if (!storage->GetString(id, key, value)) {
    *value = default_value;
  }
}

// static
void Service::SaveStringOrClear(StoreInterface* storage,
                                const std::string& id,
                                const std::string& key,
                                const std::string& value) {
  if (value.empty()) {
    storage->DeleteKey(id, key);
    return;
  }
  storage->SetString(id, key, value);
}

// static
void Service::SetNextSerialNumberForTesting(unsigned int next_serial_number) {
  next_serial_number_ = next_serial_number;
}

std::map<RpcIdentifier, std::string> Service::GetLoadableProfileEntries() {
  return manager_->GetLoadableProfileEntriesForService(this);
}

std::string Service::CalculateState(Error* /*error*/) {
  return GetStateString();
}

std::string Service::CalculateTechnology(Error* /*error*/) {
  return GetTechnologyString();
}

Service::TetheringState Service::GetTethering() const {
  return TetheringState::kUnknown;
}

void Service::IgnoreParameterForConfigure(const std::string& parameter) {
  parameters_ignored_for_configure_.insert(parameter);
}

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
const std::string& Service::GetEAPKeyManagement() const {
  CHECK(eap());
  return eap()->key_management();
}

void Service::SetEAPKeyManagement(const std::string& key_management) {
  CHECK(mutable_eap());
  mutable_eap()->SetKeyManagement(key_management, nullptr);
}
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

bool Service::GetAutoConnect(Error* /*error*/) {
  return auto_connect();
}

bool Service::SetAutoConnectFull(const bool& connect, Error* /*error*/) {
  LOG(INFO) << "Service " << log_name() << ": AutoConnect=" << auto_connect()
            << "->" << connect;
  if (!retain_auto_connect_) {
    RetainAutoConnect();
    // Irrespective of an actual change in the |kAutoConnectProperty|, we must
    // flush the current value of the property to the profile.
    if (IsRemembered()) {
      SaveToProfile();
    }
  }

  if (auto_connect() == connect) {
    return false;
  }

  SetAutoConnect(connect);
  manager_->UpdateService(this);
  return true;
}

void Service::ClearAutoConnect(Error* /*error*/) {
  if (auto_connect()) {
    SetAutoConnect(false);
    manager_->UpdateService(this);
  }

  retain_auto_connect_ = false;
}

std::string Service::GetCheckPortal(Error* error) {
  return check_portal_;
}

bool Service::SetCheckPortal(const std::string& check_portal, Error* error) {
  if (check_portal != kCheckPortalFalse && check_portal != kCheckPortalTrue &&
      check_portal != kCheckPortalAuto) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        base::StringPrintf("Invalid Service CheckPortal property value: %s",
                           check_portal.c_str()));
    return false;
  }
  if (check_portal == check_portal_) {
    return false;
  }
  check_portal_ = check_portal;
  return true;
}

std::string Service::GetGuid(Error* error) {
  return guid_;
}

bool Service::SetGuid(const std::string& guid, Error* /*error*/) {
  if (guid_ == guid) {
    return false;
  }
  guid_ = guid;
  adaptor_->EmitStringChanged(kGuidProperty, guid_);
  return true;
}

void Service::RetainAutoConnect() {
  retain_auto_connect_ = true;
}

void Service::SetSecurity(CryptoAlgorithm crypto_algorithm,
                          bool key_rotation,
                          bool endpoint_auth) {
  crypto_algorithm_ = crypto_algorithm;
  key_rotation_ = key_rotation;
  endpoint_auth_ = endpoint_auth;
}

std::string Service::GetNameProperty(Error* /*error*/) {
  return friendly_name_;
}

bool Service::SetNameProperty(const std::string& name, Error* error) {
  if (name != friendly_name_) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        base::StringPrintf("Service %s Name property cannot be modified.",
                           log_name_.c_str()));
    return false;
  }
  return false;
}

void Service::SetHasEverConnected(bool has_ever_connected) {
  if (has_ever_connected_ == has_ever_connected)
    return;
  has_ever_connected_ = has_ever_connected;
}

int32_t Service::GetPriority(Error* error) {
  return priority_;
}

bool Service::SetPriority(const int32_t& priority, Error* error) {
  if (priority_ == priority) {
    return false;
  }
  priority_ = priority;
  adaptor_->EmitIntChanged(kPriorityProperty, priority_);
  return true;
}

std::string Service::GetProfileRpcId(Error* error) {
  if (!profile_) {
    // This happens in some unit tests where profile_ is not set.
    error->Populate(Error::kNotFound);
    return RpcIdentifier().value();
  }
  return profile_->GetRpcIdentifier().value();
}

bool Service::SetProfileRpcId(const std::string& profile, Error* error) {
  if (profile_ && profile_->GetRpcIdentifier().value() == profile) {
    return false;
  }
  ProfileConstRefPtr old_profile = profile_;
  // No need to Emit afterwards, since SetProfileForService will call
  // into SetProfile (if the profile actually changes).
  manager_->SetProfileForService(this, profile, error);
  // Can't just use error.IsSuccess(), because that also requires saving
  // the profile to succeed. (See Profile::AdoptService)
  return (profile_ != old_profile);
}

std::string Service::GetProxyConfig(Error* error) {
  return proxy_config_;
}

bool Service::SetProxyConfig(const std::string& proxy_config, Error* error) {
  if (proxy_config_ == proxy_config)
    return false;
  proxy_config_ = proxy_config;
  adaptor_->EmitStringChanged(kProxyConfigProperty, proxy_config_);
  return true;
}

void Service::NotifyIfVisibilityChanged() {
  const bool is_visible = IsVisible();
  if (was_visible_ != is_visible)
    adaptor_->EmitBoolChanged(kVisibleProperty, is_visible);
  was_visible_ = is_visible;
}

Strings Service::GetDisconnectsProperty(Error* /*error*/) const {
  return disconnects_.ExtractWallClockToStrings();
}

Strings Service::GetMisconnectsProperty(Error* /*error*/) const {
  return misconnects_.ExtractWallClockToStrings();
}

uint64_t Service::GetTrafficCounterResetTimeProperty(Error* /*error*/) const {
  return traffic_counter_reset_time_.ToDeltaSinceWindowsEpoch()
      .InMilliseconds();
}

bool Service::GetMeteredProperty(Error* /*error*/) {
  return IsMetered();
}

bool Service::SetMeteredProperty(const bool& metered, Error* /*error*/) {
  // We always want to set the override, but only emit a signal if
  // the value has actually changed as a result.
  bool was_metered = IsMetered();
  metered_override_ = metered;

  if (was_metered == metered) {
    return false;
  }
  adaptor_->EmitBoolChanged(kMeteredProperty, metered);
  return true;
}

void Service::ClearMeteredProperty(Error* /*error*/) {
  bool was_metered = IsMetered();
  metered_override_ = std::nullopt;

  bool is_metered = IsMetered();
  if (was_metered != is_metered)
    adaptor_->EmitBoolChanged(kMeteredProperty, is_metered);
}

std::string Service::GetONCSource(Error* error) {
  if (toUnderlying(source_) >= ONCSourceMapping.size()) {
    LOG(WARNING) << "Bad source value: " << toUnderlying(source_);
    return kONCSourceUnknown;
  }

  return ONCSourceMapping[toUnderlying(source_)];
}

bool Service::SetONCSource(const std::string& source, Error* error) {
  if (ONCSourceMapping[toUnderlying(source_)] == source) {
    return false;
  }
  auto it = std::find(ONCSourceMapping.begin(), ONCSourceMapping.end(), source);
  if (it == ONCSourceMapping.end()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        base::StringPrintf("Service %s: Source property value %s invalid.",
                           log_name_.c_str(), source.c_str()));
    return false;
  }
  source_ = static_cast<ONCSource>(std::distance(ONCSourceMapping.begin(), it));
  adaptor_->EmitStringChanged(kONCSourceProperty,
                              ONCSourceMapping[toUnderlying(source_)]);
  return true;
}

int Service::SourcePriority() {
  static constexpr std::array<Service::ONCSource,
                              toUnderlying(Service::ONCSource::kONCSourcesNum)>
      priorities = {Service::ONCSource::kONCSourceUnknown,
                    Service::ONCSource::kONCSourceNone,
                    Service::ONCSource::kONCSourceUserImport,
                    Service::ONCSource::kONCSourceDevicePolicy,
                    Service::ONCSource::kONCSourceUserPolicy};

  auto it = std::find(priorities.begin(), priorities.end(), Source());
  DCHECK(it != priorities.end());
  return std::distance(priorities.begin(), it);
}

bool Service::GetVisibleProperty(Error* /*error*/) {
  return IsVisible();
}

void Service::SaveToProfile() {
  if (profile_.get() && profile_->GetConstStorage()) {
    profile_->UpdateService(this);
  }
}

void Service::SetFriendlyName(const std::string& friendly_name) {
  if (friendly_name == friendly_name_)
    return;
  friendly_name_ = friendly_name;
  adaptor()->EmitStringChanged(kNameProperty, friendly_name_);
}

void Service::SetStrength(uint8_t strength) {
  if (strength == strength_) {
    return;
  }
  strength_ = strength;
  adaptor_->EmitUint8Changed(kSignalStrengthProperty, strength);
}

void Service::SetErrorDetails(const std::string& details) {
  if (error_details_ == details) {
    return;
  }
  error_details_ = details;
  adaptor_->EmitStringChanged(kErrorDetailsProperty, error_details_);
}

void Service::UpdateErrorProperty() {
  const std::string error(ConnectFailureToString(failure_));
  if (error == error_) {
    return;
  }
  LOG(INFO) << __func__ << ": " << error;
  error_ = error;
  adaptor_->EmitStringChanged(kErrorProperty, error);
}

void Service::ClearExplicitlyDisconnected() {
  if (explicitly_disconnected_) {
    explicitly_disconnected_ = false;
    manager_->UpdateService(this);
  }
}

EventDispatcher* Service::dispatcher() const {
  return manager_->dispatcher();
}

Metrics* Service::metrics() const {
  return manager_->metrics();
}

}  // namespace shill
