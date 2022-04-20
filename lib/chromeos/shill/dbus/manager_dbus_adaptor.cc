// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/manager_dbus_adaptor.h"

#include <utility>

#include <base/bind.h>
#include <base/callback.h>
//#include <base/check.h>
#include <base/logging.h>

#include "shill/callbacks.h"
#include "shill/dbus/dbus_service_watcher_factory.h"
#include "shill/device.h"
#include "shill/error.h"
#include "shill/geolocation_info.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/store/key_value_store.h"
#include "shill/store/property_store.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const ManagerDBusAdaptor* m) {
  return m->GetRpcIdentifier().value();
}
}  // namespace Logging

// static
const char ManagerDBusAdaptor::kPath[] = "/";

ManagerDBusAdaptor::ManagerDBusAdaptor(
    const scoped_refptr<dbus::Bus>& adaptor_bus,
    const scoped_refptr<dbus::Bus> proxy_bus,
    Manager* manager)
    : org::chromium::flimflam::ManagerAdaptor(this),
      DBusAdaptor(adaptor_bus, kPath),
      manager_(manager),
      proxy_bus_(proxy_bus),
      dbus_service_watcher_factory_(DBusServiceWatcherFactory::GetInstance()) {}

ManagerDBusAdaptor::~ManagerDBusAdaptor() {
  manager_ = nullptr;
}

void ManagerDBusAdaptor::RegisterAsync(
    const base::Callback<void(bool)>& completion_callback) {
  RegisterWithDBusObject(dbus_object());
  dbus_object()->RegisterAsync(completion_callback);
}

void ManagerDBusAdaptor::EmitBoolChanged(const std::string& name, bool value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ManagerDBusAdaptor::EmitUintChanged(const std::string& name,
                                         uint32_t value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ManagerDBusAdaptor::EmitIntChanged(const std::string& name, int value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ManagerDBusAdaptor::EmitStringChanged(const std::string& name,
                                           const std::string& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ManagerDBusAdaptor::EmitStringsChanged(
    const std::string& name, const std::vector<std::string>& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ManagerDBusAdaptor::EmitKeyValueStoreChanged(const std::string& name,
                                                  const KeyValueStore& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(value);
  SendPropertyChangedSignal(name, brillo::Any(dict));
}

void ManagerDBusAdaptor::EmitRpcIdentifierChanged(const std::string& name,
                                                  const RpcIdentifier& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ManagerDBusAdaptor::EmitRpcIdentifierArrayChanged(
    const std::string& name, const RpcIdentifiers& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

bool ManagerDBusAdaptor::GetProperties(brillo::ErrorPtr* error,
                                       brillo::VariantDictionary* properties) {
  SLOG(this, 2) << __func__;
  return DBusAdaptor::GetProperties(manager_->store(), properties, error);
}

bool ManagerDBusAdaptor::SetProperty(brillo::ErrorPtr* error,
                                     const std::string& name,
                                     const brillo::Any& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  return DBusAdaptor::SetProperty(manager_->mutable_store(), name, value,
                                  error);
}

bool ManagerDBusAdaptor::GetState(brillo::ErrorPtr* /*error*/,
                                  std::string* state) {
  SLOG(this, 2) << __func__;
  *state = manager_->CalculateState(nullptr);
  return true;
}

bool ManagerDBusAdaptor::CreateProfile(brillo::ErrorPtr* error,
                                       const std::string& name,
                                       dbus::ObjectPath* profile_path) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  std::string path;
  manager_->CreateProfile(name, &path, &e);
  if (e.ToChromeosError(error)) {
    return false;
  }
  *profile_path = dbus::ObjectPath(path);
  return true;
}

bool ManagerDBusAdaptor::RemoveProfile(brillo::ErrorPtr* error,
                                       const std::string& name) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  manager_->RemoveProfile(name, &e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::PushProfile(brillo::ErrorPtr* error,
                                     const std::string& name,
                                     dbus::ObjectPath* profile_path) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  std::string path;
  manager_->PushProfile(name, &path, &e);
  if (e.ToChromeosError(error)) {
    return false;
  }
  *profile_path = dbus::ObjectPath(path);
  return true;
}

bool ManagerDBusAdaptor::InsertUserProfile(brillo::ErrorPtr* error,
                                           const std::string& name,
                                           const std::string& user_hash,
                                           dbus::ObjectPath* profile_path) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  std::string path;
  manager_->InsertUserProfile(name, user_hash, &path, &e);
  if (e.ToChromeosError(error)) {
    return false;
  }
  *profile_path = dbus::ObjectPath(path);
  return true;
}

bool ManagerDBusAdaptor::PopProfile(brillo::ErrorPtr* error,
                                    const std::string& name) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  manager_->PopProfile(name, &e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::PopAnyProfile(brillo::ErrorPtr* error) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->PopAnyProfile(&e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::PopAllUserProfiles(brillo::ErrorPtr* error) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->PopAllUserProfiles(&e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::RecheckPortal(brillo::ErrorPtr* error) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->RecheckPortal(&e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::RequestScan(brillo::ErrorPtr* error,
                                     const std::string& technology) {  // NOLINT
  SLOG(this, 2) << __func__ << ": " << technology;
  Error e;
  manager_->RequestScan(technology, &e);
  return !e.ToChromeosError(error);
}

void ManagerDBusAdaptor::SetNetworkThrottlingStatus(
    DBusMethodResponsePtr<> response,
    bool enabled,
    uint32_t upload_rate_kbits,
    uint32_t download_rate_kbits) {
  SLOG(this, 2) << __func__ << ": " << enabled;
  ResultCallback callback = GetMethodReplyCallback(std::move(response));
  manager_->SetNetworkThrottlingStatus(callback, enabled, upload_rate_kbits,
                                       download_rate_kbits);
  return;
}

void ManagerDBusAdaptor::EnableTechnology(DBusMethodResponsePtr<> response,
                                          const std::string& technology_name) {
  SLOG(this, 2) << __func__ << ": " << technology_name;
  Error e(Error::kOperationInitiated);
  ResultCallback callback = GetMethodReplyCallback(std::move(response));
  const bool kPersistentSave = true;
  manager_->SetEnabledStateForTechnology(technology_name, true, kPersistentSave,
                                         callback);
}

void ManagerDBusAdaptor::DisableTechnology(DBusMethodResponsePtr<> response,
                                           const std::string& technology_name) {
  SLOG(this, 2) << __func__ << ": " << technology_name;
  Error e(Error::kOperationInitiated);
  ResultCallback callback = GetMethodReplyCallback(std::move(response));
  const bool kPersistentSave = true;
  manager_->SetEnabledStateForTechnology(technology_name, false,
                                         kPersistentSave, callback);
}

// Called, e.g., to get WiFiService handle for a hidden SSID.
bool ManagerDBusAdaptor::GetService(brillo::ErrorPtr* error,
                                    const brillo::VariantDictionary& args,
                                    dbus::ObjectPath* service_path) {
  SLOG(this, 2) << __func__;
  ServiceRefPtr service;
  Error e;
  KeyValueStore args_store = KeyValueStore::ConvertFromVariantDictionary(args);
  service = manager_->GetService(args_store, &e);
  if (e.ToChromeosError(error)) {
    return false;
  }
  *service_path = service->GetRpcIdentifier();
  return true;
}

bool ManagerDBusAdaptor::ConfigureService(brillo::ErrorPtr* error,
                                          const brillo::VariantDictionary& args,
                                          dbus::ObjectPath* service_path) {
  SLOG(this, 2) << __func__;
  ServiceRefPtr service;
  KeyValueStore args_store = KeyValueStore::ConvertFromVariantDictionary(args);
  Error configure_error;
  service = manager_->ConfigureService(args_store, &configure_error);
  if (configure_error.ToChromeosError(error)) {
    return false;
  }
  *service_path = service->GetRpcIdentifier();
  return true;
}

bool ManagerDBusAdaptor::ConfigureServiceForProfile(
    brillo::ErrorPtr* error,
    const dbus::ObjectPath& profile_rpcid,
    const brillo::VariantDictionary& args,
    dbus::ObjectPath* service_path) {
  SLOG(this, 2) << __func__;
  ServiceRefPtr service;
  KeyValueStore args_store = KeyValueStore::ConvertFromVariantDictionary(args);
  Error configure_error;
  service = manager_->ConfigureServiceForProfile(profile_rpcid.value(),
                                                 args_store, &configure_error);
  if (configure_error.ToChromeosError(error)) {
    return false;
  }
  CHECK(service);
  *service_path = service->GetRpcIdentifier();
  return true;
}

bool ManagerDBusAdaptor::FindMatchingService(
    brillo::ErrorPtr* error,
    const brillo::VariantDictionary& args,
    dbus::ObjectPath* service_path) {  // NOLINT
  SLOG(this, 2) << __func__;
  KeyValueStore args_store = KeyValueStore::ConvertFromVariantDictionary(args);

  Error find_error;
  ServiceRefPtr service =
      manager_->FindMatchingService(args_store, &find_error);
  if (find_error.type() == Error::kNotFound) {
    // FindMatchingService may be used to test whether a Service exists.
    LOG(INFO) << "FindMatchingService failed: " << find_error;
    find_error.ToChromeosErrorNoLog(error);
    return false;
  } else if (find_error.ToChromeosError(error)) {
    return false;
  }

  *service_path = service->GetRpcIdentifier();
  return true;
}

bool ManagerDBusAdaptor::GetDebugLevel(brillo::ErrorPtr* /*error*/,
                                       int32_t* level) {
  SLOG(this, 2) << __func__;
  *level = logging::GetMinLogLevel();
  return true;
}

bool ManagerDBusAdaptor::SetDebugLevel(brillo::ErrorPtr* /*error*/,
                                       int32_t level) {
  SLOG(this, 2) << __func__ << ": " << level;
  if (level < logging::LOGGING_NUM_SEVERITIES) {
    logging::SetMinLogLevel(level);
    // Like VLOG, SLOG uses negative verbose level.
    ScopeLogger::GetInstance()->set_verbose_level(-level);
  } else {
    LOG(WARNING) << "Ignoring attempt to set log level to " << level;
  }
  return true;
}

bool ManagerDBusAdaptor::GetServiceOrder(brillo::ErrorPtr* /*error*/,
                                         std::string* order) {
  SLOG(this, 2) << __func__;
  *order = manager_->GetTechnologyOrder();
  return true;
}

bool ManagerDBusAdaptor::SetServiceOrder(brillo::ErrorPtr* error,
                                         const std::string& order) {
  SLOG(this, 2) << __func__ << ": " << order;
  Error e;
  manager_->SetTechnologyOrder(order, &e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::GetDebugTags(brillo::ErrorPtr* /*error*/,
                                      std::string* tags) {
  SLOG(this, 2) << __func__;
  *tags = ScopeLogger::GetInstance()->GetEnabledScopeNames();
  return true;
}

bool ManagerDBusAdaptor::SetDebugTags(brillo::ErrorPtr* /*error*/,
                                      const std::string& tags) {
  SLOG(this, 2) << __func__ << ": " << tags;
  ScopeLogger::GetInstance()->EnableScopesByName(tags);
  return true;
}

bool ManagerDBusAdaptor::ListDebugTags(brillo::ErrorPtr* /*error*/,
                                       std::string* tags) {
  SLOG(this, 2) << __func__;
  *tags = ScopeLogger::GetInstance()->GetAllScopeNames();
  return true;
}

bool ManagerDBusAdaptor::GetNetworksForGeolocation(
    brillo::ErrorPtr* /*error*/, brillo::VariantDictionary* networks) {
  SLOG(this, 2) << __func__;
  for (const auto& network : manager_->GetNetworksForGeolocation()) {
    networks->emplace(network.first, brillo::Any(network.second));
  }
  return true;
}

bool ManagerDBusAdaptor::ScanAndConnectToBestServices(brillo::ErrorPtr* error) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->ScanAndConnectToBestServices(&e);
  return !e.ToChromeosError(error);
}

// TODO(b:206907629): Remove the D-Bus method when chrome is not calling it
// anymore.
bool ManagerDBusAdaptor::ConnectToBestServices(brillo::ErrorPtr* error) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->ConnectToBestServices(&e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::CreateConnectivityReport(brillo::ErrorPtr* error) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->CreateConnectivityReport(&e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::ClaimInterface(brillo::ErrorPtr* error,
                                        dbus::Message* message,
                                        const std::string& claimer_name,
                                        const std::string& interface_name) {
  SLOG(this, 2) << __func__;
  Error e;
  // Empty claimer name is used to indicate default claimer.
  // TODO(samueltan): update this API or make a new API to use a flag to
  // indicate default claimer instead (b/27924738).
  std::string claimer = (claimer_name == "" ? "" : message->GetSender());
  manager_->ClaimDevice(claimer, interface_name, &e);
  if (e.IsSuccess() && claimer_name != "") {
    // Only setup watcher for non-default claimer.
    watcher_for_device_claimer_ =
        dbus_service_watcher_factory_->CreateDBusServiceWatcher(
            proxy_bus_, claimer,
            base::Bind(&ManagerDBusAdaptor::OnDeviceClaimerVanished,
                       base::Unretained(this)));
  }
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::ReleaseInterface(brillo::ErrorPtr* error,
                                          dbus::Message* message,
                                          const std::string& claimer_name,
                                          const std::string& interface_name) {
  SLOG(this, 2) << __func__;
  Error e;
  bool claimer_removed;
  // Empty claimer name is used to indicate default claimer.
  // TODO(samueltan): update this API or make a new API to use a flag to
  // indicate default claimer instead (b/27924738).
  manager_->ReleaseDevice(claimer_name == "" ? "" : message->GetSender(),
                          interface_name, &claimer_removed, &e);
  if (claimer_removed) {
    watcher_for_device_claimer_.reset();
  }
  return !e.ToChromeosError(error);
}

void ManagerDBusAdaptor::OnDeviceClaimerVanished() {
  SLOG(this, 3) << __func__;
  manager_->OnDeviceClaimerVanished();
  watcher_for_device_claimer_.reset();
}

bool ManagerDBusAdaptor::SetDNSProxyAddresses(
    brillo::ErrorPtr* error, const std::vector<std::string>& addresses) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->SetDNSProxyAddresses(addresses, &e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::ClearDNSProxyAddresses(brillo::ErrorPtr* /* error */) {
  SLOG(this, 2) << __func__;
  manager_->ClearDNSProxyAddresses();
  return true;
}

bool ManagerDBusAdaptor::SetDNSProxyDOHProviders(
    brillo::ErrorPtr* error, const brillo::VariantDictionary& providers) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->SetDNSProxyDOHProviders(
      KeyValueStore::ConvertFromVariantDictionary(providers), &e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::AddPasspointCredentials(
    brillo::ErrorPtr* error,
    const dbus::ObjectPath& profile_rpcid,
    const brillo::VariantDictionary& args) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->AddPasspointCredentials(
      profile_rpcid.value(), KeyValueStore::ConvertFromVariantDictionary(args),
      &e);
  return !e.ToChromeosError(error);
}

bool ManagerDBusAdaptor::RemovePasspointCredentials(
    brillo::ErrorPtr* error,
    const dbus::ObjectPath& profile_rpcid,
    const brillo::VariantDictionary& args) {
  SLOG(this, 2) << __func__;
  Error e;
  manager_->RemovePasspointCredentials(
      profile_rpcid.value(), KeyValueStore::ConvertFromVariantDictionary(args),
      &e);
  return !e.ToChromeosError(error);
}
}  // namespace shill
