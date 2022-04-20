// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_service.h"

#include <algorithm>
#include <utility>

//#include <base/check.h>
//#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/dbus/dbus_control.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/ppp_device.h"
#include "shill/profile.h"
#include "shill/store/key_value_store.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"
#include "shill/technology.h"
#include "shill/vpn/vpn_driver.h"
#include "shill/vpn/vpn_provider.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
static std::string ObjectID(const VPNService* s) {
  return s->log_name();
}
}  // namespace Logging

const char VPNService::kAutoConnNeverConnected[] = "never connected";
const char VPNService::kAutoConnVPNAlreadyActive[] = "vpn already active";

VPNService::VPNService(Manager* manager, std::unique_ptr<VPNDriver> driver)
    : Service(manager, Technology::kVPN),
      driver_(std::move(driver)),
      last_default_physical_service_online_(manager->IsOnline()) {
  if (driver_) {
    log_name_ = "vpn_" + driver_->GetProviderType() + "_" +
                base::NumberToString(serial_number());
  } else {
    // |driver| may be null in tests.
    log_name_ = "vpn_" + base::NumberToString(serial_number());
  }
  SetConnectable(true);
  set_save_credentials(false);
  mutable_store()->RegisterDerivedString(
      kPhysicalTechnologyProperty,
      StringAccessor(new CustomAccessor<VPNService, std::string>(
          this, &VPNService::GetPhysicalTechnologyProperty, nullptr)));
  this->manager()->AddDefaultServiceObserver(this);
}

VPNService::~VPNService() {
  manager()->RemoveDefaultServiceObserver(this);
}

void VPNService::OnConnect(Error* error) {
  manager()->vpn_provider()->DisconnectAll();
  // Note that this must be called after VPNProvider::DisconnectAll. While most
  // VPNDrivers create their own Devices, ArcVpnDriver shares the same
  // VirtualDevice (VPNProvider::arc_device), so Disconnect()ing an ARC
  // VPNService after completing the connection for a new ARC VPNService will
  // cause the arc_device to be disabled at the end of this call.

  if (manager()->IsTechnologyProhibited(Technology::kVPN)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kPermissionDenied,
                          "VPN is prohibited.");
    return;
  }

  SetState(ConnectState::kStateAssociating);
  // driver_ is owned by VPNService, so this is safe.
  base::TimeDelta timeout = driver_->ConnectAsync(this);
  StartDriverConnectTimeout(timeout);
}

void VPNService::OnDisconnect(Error* error, const char* reason) {
  StopDriverConnectTimeout();
  SetState(ConnectState::kStateDisconnecting);
  driver_->Disconnect();
  CleanupDevice();

  SetState(ConnectState::kStateIdle);
}

void VPNService::OnDriverConnected(const std::string& if_name, int if_index) {
  StopDriverConnectTimeout();
  if (!CreateDevice(if_name, if_index)) {
    LOG(ERROR) << "Cannot create VPN device for " << if_name;
    SetFailure(Service::kFailureInternal);
    SetErrorDetails(Service::kErrorDetailsNone);
    return;
  }
  if (driver_->GetProviderType() == std::string(kProviderArcVpn)) {
    device_->SetFixedIpParams(true);
  }

  SetState(ConnectState::kStateConfiguring);
  ConfigureDevice();
  SetState(ConnectState::kStateConnected);
  SetState(ConnectState::kStateOnline);
}

void VPNService::OnDriverFailure(ConnectFailure failure,
                                 const std::string& error_details) {
  StopDriverConnectTimeout();
  CleanupDevice();
  SetErrorDetails(error_details);
  SetFailure(failure);
}

void VPNService::OnDriverReconnecting(base::TimeDelta timeout) {
  StartDriverConnectTimeout(timeout);
  SetState(Service::kStateAssociating);
  // If physical network changes before driver connection finished, this could
  // be called before device_ was initialized.
  if (!device_)
    return;
  device_->ResetConnection();
}

bool VPNService::CreateDevice(const std::string& if_name, int if_index) {
  // Avoids recreating a VirtualDevice if the network interface is not changed.
  if (device_ != nullptr && device_->link_name() == if_name &&
      device_->interface_index() == if_index) {
    return true;
  }
  // Resets af first to avoid crashing shill in some cases. See
  // b/172228079#comment6.
  device_ = nullptr;
  device_ = new VirtualDevice(manager(), if_name, if_index, Technology::kVPN);
  return device_ != nullptr;
}

void VPNService::CleanupDevice() {
  if (!device_)
    return;
  device_->DropConnection();
  device_->SetEnabled(false);
  device_ = nullptr;
}

void VPNService::ConfigureDevice() {
  if (!device_) {
    LOG(DFATAL) << "Device not created yet.";
    return;
  }

  device_->SetEnabled(true);
  device_->SelectService(this);
  device_->UpdateIPConfig(driver_->GetIPProperties());
}

std::string VPNService::GetStorageIdentifier() const {
  return storage_id_;
}

bool VPNService::IsAlwaysOnVpn(const std::string& package) const {
  // For ArcVPN connections, the driver host is set to the package name of the
  // Android app that is creating the VPN connection.
  return driver_->GetProviderType() == std::string(kProviderArcVpn) &&
         driver_->GetHost() == package;
}

// static
std::string VPNService::CreateStorageIdentifier(const KeyValueStore& args,
                                                Error* error) {
  const auto host = args.Lookup<std::string>(kProviderHostProperty, "");
  if (host.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidProperty,
                          "Missing VPN host.");
    return "";
  }
  const auto name = args.Lookup<std::string>(kNameProperty, "");
  if (name.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidProperty,
                          "Missing VPN name.");
    return "";
  }
  return SanitizeStorageIdentifier(
      base::StringPrintf("vpn_%s_%s", host.c_str(), name.c_str()));
}

std::string VPNService::GetPhysicalTechnologyProperty(Error* error) {
  ServiceRefPtr underlying_service = manager()->GetPrimaryPhysicalService();
  if (!underlying_service) {
    error->Populate(Error::kOperationFailed);
    return "";
  }

  return underlying_service->technology().GetName();
}

RpcIdentifier VPNService::GetDeviceRpcId(Error* error) const {
  if (!device_) {
    error->Populate(Error::kNotFound, "Not associated with a device");
    return DBusControl::NullRpcIdentifier();
  }
  return device_->GetRpcIdentifier();
}

bool VPNService::Load(const StoreInterface* storage) {
  return Service::Load(storage) &&
         driver_->Load(storage, GetStorageIdentifier());
}

void VPNService::MigrateDeprecatedStorage(StoreInterface* storage) {
  Service::MigrateDeprecatedStorage(storage);

  const std::string id = GetStorageIdentifier();
  CHECK(storage->ContainsGroup(id));
  driver_->MigrateDeprecatedStorage(storage, id);
}

bool VPNService::Save(StoreInterface* storage) {
  return Service::Save(storage) &&
         driver_->Save(storage, GetStorageIdentifier(), save_credentials());
}

bool VPNService::Unload() {
  // The base method also disconnects the service.
  Service::Unload();

  set_save_credentials(false);
  driver_->UnloadCredentials();

  // Ask the VPN provider to remove us from its list.
  manager()->vpn_provider()->RemoveService(this);

  return true;
}

void VPNService::InitDriverPropertyStore() {
  driver_->InitPropertyStore(mutable_store());
}

bool VPNService::SupportsAlwaysOnVpn() {
  // ARC VPNs are not supporting always-on VPN through Shill.
  return driver()->GetProviderType() != kProviderArcVpn;
}

void VPNService::EnableAndRetainAutoConnect() {
  // The base EnableAndRetainAutoConnect method also sets auto_connect_ to true
  // which is not desirable for VPN services.
  RetainAutoConnect();
}

bool VPNService::IsAutoConnectable(const char** reason) const {
  if (!Service::IsAutoConnectable(reason)) {
    return false;
  }
  // Don't auto-connect VPN services that have never connected. This improves
  // the chances that the VPN service is connectable and avoids dialog popups.
  if (!has_ever_connected()) {
    *reason = kAutoConnNeverConnected;
    return false;
  }
  // Don't auto-connect a VPN service if another VPN service is already active.
  if (manager()->vpn_provider()->HasActiveService()) {
    *reason = kAutoConnVPNAlreadyActive;
    return false;
  }
  return true;
}

Service::TetheringState VPNService::GetTethering() const {
  if (!IsConnected()) {
    return TetheringState::kUnknown;
  }
  ServiceRefPtr underlying_service = manager()->GetPrimaryPhysicalService();
  if (!underlying_service) {
    return TetheringState::kUnknown;
  }
  return underlying_service->GetTethering();
}

bool VPNService::SetNameProperty(const std::string& name, Error* error) {
  if (name == friendly_name()) {
    return false;
  }
  LOG(INFO) << "SetNameProperty called for: " << log_name();

  KeyValueStore* args = driver_->args();
  args->Set<std::string>(kNameProperty, name);
  const auto new_storage_id = CreateStorageIdentifier(*args, error);
  if (new_storage_id.empty()) {
    return false;
  }
  auto old_storage_id = storage_id_;
  DCHECK_NE(old_storage_id, new_storage_id);

  SetFriendlyName(name);

  // Update the storage identifier before invoking DeleteEntry to prevent it
  // from unloading this service.
  storage_id_ = new_storage_id;
  profile()->DeleteEntry(old_storage_id, nullptr);
  profile()->UpdateService(this);
  return true;
}

VirtualDeviceRefPtr VPNService::GetVirtualDevice() const {
  return device_;
}

void VPNService::OnBeforeSuspend(const ResultCallback& callback) {
  driver_->OnBeforeSuspend(callback);
}

void VPNService::OnAfterResume() {
  driver_->OnAfterResume();
  Service::OnAfterResume();
}

void VPNService::OnDefaultLogicalServiceChanged(const ServiceRefPtr&) {}

void VPNService::OnDefaultPhysicalServiceChanged(
    const ServiceRefPtr& physical_service) {
  SLOG(this, 2) << __func__ << "("
                << (physical_service ? physical_service->log_name() : "-")
                << ")";

  bool default_physical_service_online =
      physical_service && physical_service->IsOnline();
  const std::string physical_service_path =
      physical_service ? physical_service->GetDBusObjectPathIdentifer() : "";

  if (!last_default_physical_service_online_ &&
      default_physical_service_online) {
    driver_->OnDefaultPhysicalServiceEvent(
        VPNDriver::kDefaultPhysicalServiceUp);
  } else if (last_default_physical_service_online_ &&
             !default_physical_service_online) {
    // The default physical service is not online, and nothing else is available
    // right now. All we can do is wait.
    SLOG(this, 2) << __func__ << " - physical service lost or is not online";
    driver_->OnDefaultPhysicalServiceEvent(
        VPNDriver::kDefaultPhysicalServiceDown);
  } else if (last_default_physical_service_online_ &&
             default_physical_service_online &&
             physical_service_path != last_default_physical_service_path_) {
    // The original service is no longer the default, but manager was able
    // to find another physical service that is already Online.
    driver_->OnDefaultPhysicalServiceEvent(
        VPNDriver::kDefaultPhysicalServiceChanged);
  }

  last_default_physical_service_online_ = default_physical_service_online;
  last_default_physical_service_path_ = physical_service_path;
}

void VPNService::StartDriverConnectTimeout(base::TimeDelta timeout) {
  if (timeout == VPNDriver::kTimeoutNone) {
    StopDriverConnectTimeout();
    return;
  }
  LOG(INFO) << "Schedule VPN connect timeout: " << timeout.InSeconds()
            << " seconds.";
  driver_connect_timeout_callback_.Reset(
      Bind(&VPNService::OnDriverConnectTimeout, weak_factory_.GetWeakPtr()));
  dispatcher()->PostDelayedTask(
      FROM_HERE, driver_connect_timeout_callback_.callback(), timeout);
}

void VPNService::StopDriverConnectTimeout() {
  SLOG(this, 2) << __func__;
  driver_connect_timeout_callback_.Cancel();
}

void VPNService::OnDriverConnectTimeout() {
  LOG(INFO) << "VPN connect timeout.";
  driver_->OnConnectTimeout();
  StopDriverConnectTimeout();
}

}  // namespace shill
