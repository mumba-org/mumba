// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_service.h"

#include <optional>

//#include <base/check.h>
//#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/adaptor_interfaces.h"
#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_consts.h"
#include "shill/cellular/cellular_service_provider.h"
#include "shill/dbus/dbus_control.h"
#include "shill/manager.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
static std::string ObjectID(const CellularService* c) {
  return c->log_name();
}
}  // namespace Logging

// statics
const char CellularService::kAutoConnActivating[] = "activating";
const char CellularService::kAutoConnBadPPPCredentials[] =
    "bad PPP credentials";
const char CellularService::kAutoConnDeviceDisabled[] = "device disabled";
const char CellularService::kAutoConnNotRegistered[] =
    "cellular not registered";
const char CellularService::kAutoConnOutOfCredits[] = "service out of credits";
const char CellularService::kAutoConnSimUnselected[] = "SIM not selected";
const char CellularService::kAutoConnConnectFailed[] =
    "previous connect failed";
const char CellularService::kAutoConnInhibited[] = "inhibited";
const char CellularService::kStorageIccid[] = "Cellular.Iccid";
const char CellularService::kStorageImsi[] = "Cellular.Imsi";
const char CellularService::kStoragePPPUsername[] = "Cellular.PPP.Username";
const char CellularService::kStoragePPPPassword[] = "Cellular.PPP.Password";
const char CellularService::kStorageSimCardId[] = "Cellular.SimCardId";
const char CellularService::kStorageAllowRoaming[] = "Cellular.AllowRoaming";

namespace {

const char kGenericServiceNamePrefix[] = "MobileNetwork";

const char kStorageAPN[] = "Cellular.APN";
const char kStorageLastGoodAPN[] = "Cellular.LastGoodAPN";

const int kCurrentApnCacheVersion = 2;

constexpr base::TimeDelta kAutoConnectFailedTime = base::Seconds(20);

bool GetNonEmptyField(const Stringmap& stringmap,
                      const std::string& fieldname,
                      std::string* value) {
  Stringmap::const_iterator it = stringmap.find(fieldname);
  if (it != stringmap.end() && !it->second.empty()) {
    *value = it->second;
    return true;
  }
  return false;
}

void FetchDetailsFromApnList(const Stringmaps& apn_list, Stringmap* apn_info) {
  DCHECK(apn_info);
  std::string apn;
  for (const Stringmap& list_apn_info : apn_list) {
    if (GetNonEmptyField(list_apn_info, kApnProperty, &apn) &&
        (*apn_info)[kApnProperty] == apn) {
      *apn_info = list_apn_info;
      return;
    }
  }
}

bool LoadApnField(const StoreInterface* storage,
                  const std::string& storage_group,
                  const std::string& keytag,
                  const std::string& apntag,
                  Stringmap* apn_info) {
  std::string value;
  if (storage->GetString(storage_group, keytag + "." + apntag, &value) &&
      !value.empty()) {
    (*apn_info)[apntag] = value;
    return true;
  }
  return false;
}

void LoadApn(const StoreInterface* storage,
             const std::string& storage_group,
             const std::string& keytag,
             const Stringmaps& apn_list,
             Stringmap* apn_info) {
  if (keytag == kStorageLastGoodAPN) {
    // Ignore LastGoodAPN that is too old.
    int version;
    if (!LoadApnField(storage, storage_group, keytag,
                      cellular::kApnVersionProperty, apn_info) ||
        !base::StringToInt((*apn_info)[cellular::kApnVersionProperty],
                           &version) ||
        version < kCurrentApnCacheVersion) {
      return;
    }
  }

  if (!LoadApnField(storage, storage_group, keytag, kApnProperty, apn_info))
    return;
  if (keytag == kStorageAPN)
    FetchDetailsFromApnList(apn_list, apn_info);
  LoadApnField(storage, storage_group, keytag, kApnUsernameProperty, apn_info);
  LoadApnField(storage, storage_group, keytag, kApnPasswordProperty, apn_info);
  LoadApnField(storage, storage_group, keytag, kApnAuthenticationProperty,
               apn_info);
  LoadApnField(storage, storage_group, keytag, kApnIpTypeProperty, apn_info);
  LoadApnField(storage, storage_group, keytag, kApnAttachProperty, apn_info);
}

void SaveApnField(StoreInterface* storage,
                  const std::string& storage_group,
                  const Stringmap* apn_info,
                  const std::string& keytag,
                  const std::string& apntag) {
  const std::string key = keytag + "." + apntag;
  std::string str;
  if (apn_info && GetNonEmptyField(*apn_info, apntag, &str))
    storage->SetString(storage_group, key, str);
  else
    storage->DeleteKey(storage_group, key);
}

void SaveApn(StoreInterface* storage,
             const std::string& storage_group,
             const Stringmap* apn_info,
             const std::string& keytag) {
  SaveApnField(storage, storage_group, apn_info, keytag, kApnProperty);
  SaveApnField(storage, storage_group, apn_info, keytag, kApnUsernameProperty);
  SaveApnField(storage, storage_group, apn_info, keytag, kApnPasswordProperty);
  SaveApnField(storage, storage_group, apn_info, keytag,
               kApnAuthenticationProperty);
  SaveApnField(storage, storage_group, apn_info, keytag, kApnIpTypeProperty);
  SaveApnField(storage, storage_group, apn_info, keytag, kApnAttachProperty);
  SaveApnField(storage, storage_group, apn_info, keytag,
               cellular::kApnVersionProperty);
}

}  // namespace

CellularService::CellularService(Manager* manager,
                                 const std::string& imsi,
                                 const std::string& iccid,
                                 const std::string& eid)
    : Service(manager, Technology::kCellular),
      imsi_(imsi),
      iccid_(iccid),
      eid_(eid) {
  // Note: This will change once SetNetworkTechnology() is called, but the
  // serial number remains unchanged so correlating log lines will be easy.
  log_name_ = "cellular_" + base::NumberToString(serial_number());

  // This will get overwritten in Load and in Cellular::UpdateServingOperator
  // when the service is the primary service for the device.
  friendly_name_ =
      kGenericServiceNamePrefix + base::NumberToString(serial_number());

  PropertyStore* store = mutable_store();
  HelpRegisterDerivedString(kActivationTypeProperty,
                            &CellularService::CalculateActivationType, nullptr);
  store->RegisterConstString(kActivationStateProperty, &activation_state_);
  HelpRegisterDerivedStringmap(kCellularApnProperty, &CellularService::GetApn,
                               &CellularService::SetApn);
  store->RegisterConstString(kIccidProperty, &iccid_);
  store->RegisterConstString(kImsiProperty, &imsi_);
  store->RegisterConstString(kEidProperty, &eid_);
  store->RegisterConstStringmap(kCellularLastGoodApnProperty,
                                &last_good_apn_info_);
  store->RegisterConstStringmap(kCellularLastAttachApnProperty,
                                &last_attach_apn_info_);
  store->RegisterConstString(kNetworkTechnologyProperty, &network_technology_);
  HelpRegisterDerivedBool(kOutOfCreditsProperty,
                          &CellularService::IsOutOfCredits, nullptr);
  store->RegisterConstStringmap(kPaymentPortalProperty, &olp_);
  store->RegisterConstString(kRoamingStateProperty, &roaming_state_);
  store->RegisterConstStringmap(kServingOperatorProperty, &serving_operator_);
  store->RegisterConstString(kUsageURLProperty, &usage_url_);
  store->RegisterString(kCellularPPPUsernameProperty, &ppp_username_);
  store->RegisterWriteOnlyString(kCellularPPPPasswordProperty, &ppp_password_);
  mutable_store()->RegisterDerivedBool(
      kCellularAllowRoamingProperty,
      BoolAccessor(new CustomAccessor<CellularService, bool>(
          this, &CellularService::GetAllowRoaming,
          &CellularService::SetAllowRoaming)));
  storage_identifier_ = GetDefaultStorageIdentifier();
  SLOG(this, 1) << "CellularService Created: " << log_name();
}

CellularService::~CellularService() {
  SLOG(this, 1) << "CellularService Destroyed: " << log_name();
}

void CellularService::SetDevice(Cellular* device) {
  SLOG(this, 1) << __func__ << ": " << log_name()
                << " Device ICCID: " << (device ? device->iccid() : "None");
  cellular_ = device;
  Error ignored_error;
  adaptor()->EmitRpcIdentifierChanged(kDeviceProperty,
                                      GetDeviceRpcId(&ignored_error));
  adaptor()->EmitBoolChanged(kVisibleProperty,
                             GetVisibleProperty(&ignored_error));
  if (!cellular_) {
    // Do not destroy the service here, Modem may be Inhibited or have reset.
    // If it comes back, the appropriate services will be updated, created, or
    // destroyed from the available SIM properties.
    SetConnectable(false);
    SetState(kStateIdle);
    SetStrength(0);
    return;
  }

  SetConnectable(cellular_->GetConnectable(this));
  SetActivationType(kActivationTypeUnknown);
  if (cellular_->iccid() != iccid_) {
    SetState(kStateIdle);
    SetStrength(0);
  }
}

void CellularService::CompleteCellularActivation(Error* error) {
  if (!cellular_ || cellular_->service() != this) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf("CompleteCellularActivation attempted but %s "
                           "Service %s is not active.",
                           kTypeCellular, log_name().c_str()));
    return;
  }
  cellular_->CompleteActivation(error);
}

std::string CellularService::GetStorageIdentifier() const {
  return storage_identifier_;
}

std::string CellularService::GetLoadableStorageIdentifier(
    const StoreInterface& storage) const {
  std::set<std::string> groups =
      storage.GetGroupsWithProperties(GetStorageProperties());
  if (groups.empty()) {
    LOG(WARNING) << "Configuration for service " << log_name()
                 << " is not available in the persistent store";
    return std::string();
  }
  if (groups.size() == 1)
    return *groups.begin();

  // If there are multiple candidates, find the best matching entry. This may
  // happen when loading older profiles.
  LOG(WARNING) << "More than one configuration for service " << log_name()
               << " is available, using the best match and removing others.";

  // If the storage identifier matches, always use that.
  auto iter = std::find(groups.begin(), groups.end(), storage_identifier_);
  if (iter != groups.end())
    return *iter;

  // If an entry with a non-empty IMSI exists, use that.
  for (const std::string& group : groups) {
    std::string imsi;
    storage.GetString(group, kStorageImsi, &imsi);
    if (!imsi.empty())
      return group;
  }
  // Otherwise use the first entry.
  return *groups.begin();
}

bool CellularService::IsLoadableFrom(const StoreInterface& storage) const {
  return !GetLoadableStorageIdentifier(storage).empty();
}

bool CellularService::Load(const StoreInterface* storage) {
  std::string id = GetLoadableStorageIdentifier(*storage);
  if (id.empty()) {
    LOG(WARNING) << "No service with matching properties found";
    return false;
  }

  SLOG(this, 2) << __func__
                << ": Service with matching properties found: " << id;

  std::string default_storage_identifier = storage_identifier_;

  // Set |storage identifier_| to match the storage name in the Profile.
  // This needs to be done before calling Service::Load().
  // NOTE: Older profiles used other identifiers instead of ICCID. This is fine
  // since entries are identified by their properties, not the id.
  storage_identifier_ = id;

  // Load properties common to all Services.
  if (!Service::Load(storage)) {
    // Restore the default storage id. The invalid profile entry will become
    // ignored.
    storage_identifier_ = default_storage_identifier;
    return false;
  }

  // |iccid_| will always match the storage entry.
  // |eid_| is set on construction from the SIM properties.
  storage->GetString(id, kStorageImsi, &imsi_);

  // kStorageName is saved in Service but not loaded. Load the name here, but
  // only set |friendly_name_| if it is not a default name to ensure uniqueness.
  std::string friendly_name;
  if (storage->GetString(id, kStorageName, &friendly_name) &&
      !friendly_name.empty() &&
      !base::StartsWith(friendly_name, kGenericServiceNamePrefix)) {
    friendly_name_ = friendly_name;
  }

  const Stringmaps& apn_list =
      cellular() ? cellular()->apn_list() : Stringmaps();
  LoadApn(storage, id, kStorageAPN, apn_list, &apn_info_);
  LoadApn(storage, id, kStorageLastGoodAPN, apn_list, &last_good_apn_info_);

  const std::string old_username = ppp_username_;
  const std::string old_password = ppp_password_;
  storage->GetString(id, kStoragePPPUsername, &ppp_username_);
  storage->GetString(id, kStoragePPPPassword, &ppp_password_);
  if (IsFailed() && failure() == kFailurePPPAuth &&
      (old_username != ppp_username_ || old_password != ppp_password_)) {
    SetState(kStateIdle);
  }

  storage->GetBool(id, kStorageAllowRoaming, &allow_roaming_);

  return true;
}

bool CellularService::Unload() {
  Service::Unload();
  return manager()->cellular_service_provider()->OnServiceUnloaded(this);
}

bool CellularService::Save(StoreInterface* storage) {
  SLOG(this, 2) << __func__;
  // Save properties common to all Services.
  if (!Service::Save(storage))
    return false;

  const std::string id = GetStorageIdentifier();
  SaveStringOrClear(storage, id, kStorageIccid, iccid_);
  SaveStringOrClear(storage, id, kStorageImsi, imsi_);
  SaveStringOrClear(storage, id, kStorageSimCardId, GetSimCardId());

  SaveApn(storage, id, GetUserSpecifiedApn(), kStorageAPN);
  SaveApn(storage, id, GetLastGoodApn(), kStorageLastGoodAPN);
  SaveStringOrClear(storage, id, kStoragePPPUsername, ppp_username_);
  SaveStringOrClear(storage, id, kStoragePPPPassword, ppp_password_);

  storage->SetBool(id, kStorageAllowRoaming, allow_roaming_);

  return true;
}

bool CellularService::IsVisible() const {
  return true;
}

const std::string& CellularService::GetSimCardId() const {
  if (!eid_.empty())
    return eid_;
  return iccid_;
}

void CellularService::SetActivationType(ActivationType type) {
  if (type == activation_type_) {
    return;
  }
  activation_type_ = type;
  adaptor()->EmitStringChanged(kActivationTypeProperty,
                               GetActivationTypeString());
}

std::string CellularService::GetActivationTypeString() const {
  switch (activation_type_) {
    case kActivationTypeNonCellular:
      return shill::kActivationTypeNonCellular;
    case kActivationTypeOMADM:
      return shill::kActivationTypeOMADM;
    case kActivationTypeOTA:
      return shill::kActivationTypeOTA;
    case kActivationTypeOTASP:
      return shill::kActivationTypeOTASP;
    case kActivationTypeUnknown:
      return "";
    default:
      NOTREACHED();
      return "";  // Make compiler happy.
  }
}

void CellularService::SetActivationState(const std::string& state) {
  if (state == activation_state_)
    return;

  SLOG(this, 2) << __func__ << ": " << state;

  // If AutoConnect has not been explicitly set by the client, set it to true
  // when the service becomes activated.
  if (!retain_auto_connect() && state == kActivationStateActivated)
    SetAutoConnect(true);

  activation_state_ = state;
  adaptor()->EmitStringChanged(kActivationStateProperty, state);
}

void CellularService::SetOLP(const std::string& url,
                             const std::string& method,
                             const std::string& post_data) {
  Stringmap olp;
  olp[kPaymentPortalURL] = url;
  olp[kPaymentPortalMethod] = method;
  olp[kPaymentPortalPostData] = post_data;

  if (olp_ == olp) {
    return;
  }

  SLOG(this, 2) << __func__ << ": " << url;
  olp_ = olp;
  adaptor()->EmitStringmapChanged(kPaymentPortalProperty, olp);
}

void CellularService::SetUsageURL(const std::string& url) {
  if (url == usage_url_) {
    return;
  }
  usage_url_ = url;
  adaptor()->EmitStringChanged(kUsageURLProperty, url);
}

void CellularService::SetServingOperator(const Stringmap& serving_operator) {
  if (serving_operator_ == serving_operator)
    return;

  serving_operator_ = serving_operator;
  adaptor()->EmitStringmapChanged(kServingOperatorProperty, serving_operator_);
}

void CellularService::SetNetworkTechnology(const std::string& technology) {
  if (technology == network_technology_) {
    return;
  }
  network_technology_ = technology;
  log_name_ = "cellular_" + network_technology_ + "_" +
              base::NumberToString(serial_number());
  adaptor()->EmitStringChanged(kNetworkTechnologyProperty, technology);
}

void CellularService::SetRoamingState(const std::string& state) {
  if (state == roaming_state_) {
    return;
  }
  roaming_state_ = state;
  adaptor()->EmitStringChanged(kRoamingStateProperty, state);
  if (IsRoamingRuleViolated()) {
    Error error;
    OnDisconnect(&error, __func__);
  }
}

bool CellularService::IsRoamingAllowed() {
  if (cellular_ && cellular_->provider_requires_roaming())
    return true;
  return allow_roaming_ && cellular_ && cellular_->policy_allow_roaming();
}

bool CellularService::IsRoamingRuleViolated() {
  if (roaming_state_ != kRoamingStateRoaming)
    return false;

  return !IsRoamingAllowed();
}

Stringmap* CellularService::GetUserSpecifiedApn() {
  Stringmap::iterator it = apn_info_.find(kApnProperty);
  if (it == apn_info_.end() || it->second.empty())
    return nullptr;
  return &apn_info_;
}

Stringmap* CellularService::GetLastGoodApn() {
  Stringmap::iterator it = last_good_apn_info_.find(kApnProperty);
  if (it == last_good_apn_info_.end() || it->second.empty())
    return nullptr;
  return &last_good_apn_info_;
}

void CellularService::SetLastGoodApn(const Stringmap& apn_info) {
  last_good_apn_info_ = apn_info;
  adaptor()->EmitStringmapChanged(kCellularLastGoodApnProperty,
                                  last_good_apn_info_);
}

void CellularService::ClearLastGoodApn() {
  last_good_apn_info_.clear();
  adaptor()->EmitStringmapChanged(kCellularLastGoodApnProperty,
                                  last_good_apn_info_);
}

Stringmap* CellularService::GetLastAttachApn() {
  Stringmap::iterator it = last_attach_apn_info_.find(kApnProperty);
  if (it == last_attach_apn_info_.end() || it->second.empty())
    return nullptr;
  return &last_attach_apn_info_;
}

void CellularService::SetLastAttachApn(const Stringmap& apn_info) {
  last_attach_apn_info_ = apn_info;
  adaptor()->EmitStringmapChanged(kCellularLastAttachApnProperty,
                                  last_attach_apn_info_);
}

void CellularService::ClearLastAttachApn() {
  last_attach_apn_info_.clear();
  adaptor()->EmitStringmapChanged(kCellularLastAttachApnProperty,
                                  last_attach_apn_info_);
}

void CellularService::NotifySubscriptionStateChanged(
    SubscriptionState subscription_state) {
  bool new_out_of_credits =
      (subscription_state == SubscriptionState::kOutOfCredits);
  if (out_of_credits_ == new_out_of_credits)
    return;

  out_of_credits_ = new_out_of_credits;
  SLOG(this, 2) << (out_of_credits_ ? "Marking service out-of-credits"
                                    : "Marking service as not out-of-credits");
  adaptor()->EmitBoolChanged(kOutOfCreditsProperty, out_of_credits_);
}

void CellularService::OnConnect(Error* error) {
  if (!cellular_) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf("Connect attempted but %s Service %s has no device.",
                           kTypeCellular, log_name().c_str()));
    return;
  }
  cellular_->Connect(this, error);
}

void CellularService::OnDisconnect(Error* error, const char* reason) {
  if (!cellular_) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf(
            "Disconnect attempted but %s Service %s has no device.",
            kTypeCellular, log_name().c_str()));
    return;
  }
  if (cellular_->connect_pending_iccid() == iccid_) {
    cellular_->CancelPendingConnect();
    SetState(kStateIdle);
    return;
  }
  cellular_->Disconnect(error, reason);
}

bool CellularService::IsAutoConnectable(const char** reason) const {
  if (!cellular_ || !cellular_->enabled()) {
    *reason = kAutoConnDeviceDisabled;
    return false;
  }
  if (cellular_->service()) {
    if (cellular_->service()->IsConnected()) {
      *reason = kAutoConnConnected;
      return false;
    }
    if (cellular_->service()->IsConnecting()) {
      *reason = kAutoConnBusy;
      return false;
    }
  }
  if (cellular_->IsActivating()) {
    *reason = kAutoConnActivating;
    return false;
  }

  if (!Service::IsAutoConnectable(reason)) {
    return false;
  }

  if (cellular_->iccid() != iccid()) {
    *reason = kAutoConnSimUnselected;
    return false;
  }
  if (!cellular_->StateIsRegistered()) {
    *reason = kAutoConnNotRegistered;
    return false;
  }
  if (cellular_->inhibited()) {
    *reason = kAutoConnInhibited;
    return false;
  }
  if (!cellular_->connect_pending_iccid().empty()) {
    *reason = kAutoConnConnecting;
    return false;
  }
  if (failure() == kFailurePPPAuth) {
    *reason = kAutoConnBadPPPCredentials;
    return false;
  }
  if (failure() == kFailureConnect) {
    std::optional<base::TimeDelta> failed_time = GetTimeSinceFailed();
    if (failed_time && *failed_time < kAutoConnectFailedTime) {
      // For Cellular, do not immediately auto connect after a failure.
      *reason = kAutoConnConnectFailed;
      return false;
    }
  }
  if (out_of_credits_) {
    *reason = kAutoConnOutOfCredits;
    return false;
  }
  return true;
}

base::TimeDelta CellularService::GetMaxAutoConnectCooldownTime() const {
  return base::Minutes(30);
}

bool CellularService::IsDisconnectable(Error* error) const {
  if (!cellular_) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kNotConnected,
        base::StringPrintf("Disconnect attempted with no Cellular Device: %s",
                           log_name().c_str()));
    return false;
  }
  if (cellular_->connect_pending_iccid() == iccid_) {
    // Allow disconnecting when a connect is pending.
    return true;
  }
  return Service::IsDisconnectable(error);
}

bool CellularService::IsMeteredByServiceProperties() const {
  // TODO(crbug.com/989639): see if we can detect unmetered cellular
  // connections automatically.
  return true;
}

RpcIdentifier CellularService::GetDeviceRpcId(Error* error) const {
  // Only provide cellular_->GetRpcIdentifier() if this is the active service.
  if (!cellular_ || iccid() != cellular_->iccid())
    return DBusControl::NullRpcIdentifier();
  return cellular_->GetRpcIdentifier();
}

void CellularService::HelpRegisterDerivedString(
    const std::string& name,
    std::string (CellularService::*get)(Error* error),
    bool (CellularService::*set)(const std::string& value, Error* error)) {
  mutable_store()->RegisterDerivedString(
      name, StringAccessor(new CustomAccessor<CellularService, std::string>(
                this, get, set)));
}

void CellularService::HelpRegisterDerivedStringmap(
    const std::string& name,
    Stringmap (CellularService::*get)(Error* error),
    bool (CellularService::*set)(const Stringmap& value, Error* error)) {
  mutable_store()->RegisterDerivedStringmap(
      name, StringmapAccessor(new CustomAccessor<CellularService, Stringmap>(
                this, get, set)));
}

void CellularService::HelpRegisterDerivedBool(
    const std::string& name,
    bool (CellularService::*get)(Error* error),
    bool (CellularService::*set)(const bool&, Error*)) {
  mutable_store()->RegisterDerivedBool(
      name,
      BoolAccessor(new CustomAccessor<CellularService, bool>(this, get, set)));
}

std::set<std::string> CellularService::GetStorageGroupsWithProperty(
    const StoreInterface& storage,
    const std::string& key,
    const std::string& value) const {
  KeyValueStore properties;
  properties.Set<std::string>(kStorageType, kTypeCellular);
  properties.Set<std::string>(key, value);
  return storage.GetGroupsWithProperties(properties);
}

std::string CellularService::CalculateActivationType(Error* error) {
  return GetActivationTypeString();
}

Stringmap CellularService::GetApn(Error* /*error*/) {
  return apn_info_;
}

bool CellularService::SetApn(const Stringmap& value, Error* error) {
  // Only copy in the fields we care about, and validate the contents.
  // If the "apn" field is missing or empty, the APN is cleared.
  std::string new_apn;
  Stringmap new_apn_info;
  if (GetNonEmptyField(value, kApnProperty, &new_apn)) {
    new_apn_info[kApnProperty] = new_apn;

    // Fetch details from the APN database first.
    FetchDetailsFromApnList(cellular()->apn_list(), &new_apn_info);

    // If this is a user-entered APN, the one or more of the following
    // details should exist, even if they are empty.
    std::string str;
    if (GetNonEmptyField(value, kApnUsernameProperty, &str))
      new_apn_info[kApnUsernameProperty] = str;
    if (GetNonEmptyField(value, kApnPasswordProperty, &str))
      new_apn_info[kApnPasswordProperty] = str;
    if (GetNonEmptyField(value, kApnAuthenticationProperty, &str))
      new_apn_info[kApnAuthenticationProperty] = str;
    if (GetNonEmptyField(value, kApnAttachProperty, &str))
      new_apn_info[kApnAttachProperty] = str;

    new_apn_info[cellular::kApnVersionProperty] =
        base::NumberToString(kCurrentApnCacheVersion);
  }
  if (apn_info_ == new_apn_info) {
    return true;
  }
  apn_info_ = new_apn_info;
  adaptor()->EmitStringmapChanged(kCellularApnProperty, apn_info_);

  if (apn_info_.count(kApnAttachProperty) ||
      last_attach_apn_info_.count(kApnAttachProperty)) {
    // If the new APN is an 'attach APN',we need to detach and re-attach
    // to the LTE network in order to use it.
    // If we were using an attach APN, and we are no longer using it, we should
    // also re-attach to clear the attach APN in the modem.
    cellular_->ReAttach();
    return true;
  }
  if (!IsConnected()) {
    return true;
  }
  Disconnect(error, __func__);
  if (!error->IsSuccess()) {
    return false;
  }
  Connect(error, __func__);
  return error->IsSuccess();
}

KeyValueStore CellularService::GetStorageProperties() const {
  KeyValueStore properties;
  properties.Set<std::string>(kStorageType, kTypeCellular);
  properties.Set<std::string>(kStorageIccid, iccid_);
  return properties;
}
std::string CellularService::GetDefaultStorageIdentifier() const {
  if (iccid_.empty()) {
    LOG(ERROR) << "CellularService created with empty ICCID.";
    return std::string();
  }
  return SanitizeStorageIdentifier(
      base::StringPrintf("%s_%s", kTypeCellular, iccid_.c_str()));
}

bool CellularService::IsOutOfCredits(Error* /*error*/) {
  return out_of_credits_;
}

bool CellularService::SetAllowRoaming(const bool& value, Error* error) {
  SLOG(this, 2) << __func__ << ": " << value;
  if (allow_roaming_ == value)
    return false;

  allow_roaming_ = value;
  manager()->UpdateService(this);
  adaptor()->EmitBoolChanged(kCellularAllowRoamingProperty, value);

  if (IsRoamingRuleViolated()) {
    Error disconnect_error;
    OnDisconnect(&disconnect_error, __func__);
  }

  return true;
}

bool CellularService::GetAllowRoaming(Error* /*error*/) {
  return allow_roaming_;
}

}  // namespace shill
