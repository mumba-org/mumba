// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_modemcdma_proxy.h"

#include "shill/cellular/cellular_error.h"
#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

namespace mm1 {

ModemModemCdmaProxy::ModemModemCdmaProxy(const scoped_refptr<dbus::Bus>& bus,
                                         const RpcIdentifier& path,
                                         const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::ModemCdmaProxy(
          bus, service, path)) {
  // Register signal handlers.
  proxy_->RegisterActivationStateChangedSignalHandler(
      base::Bind(&ModemModemCdmaProxy::ActivationStateChanged,
                 weak_factory_.GetWeakPtr()),
      base::Bind(&ModemModemCdmaProxy::OnSignalConnected,
                 weak_factory_.GetWeakPtr()));
}

ModemModemCdmaProxy::~ModemModemCdmaProxy() = default;

void ModemModemCdmaProxy::Activate(const std::string& carrier,
                                   Error* error,
                                   const ResultCallback& callback,
                                   int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << carrier;
  proxy_->ActivateAsync(
      carrier,
      base::Bind(&ModemModemCdmaProxy::OnOperationSuccess,
                 weak_factory_.GetWeakPtr(), callback, __func__),
      base::Bind(&ModemModemCdmaProxy::OnOperationFailure,
                 weak_factory_.GetWeakPtr(), callback, __func__),
      timeout);
}

void ModemModemCdmaProxy::ActivateManual(const KeyValueStore& properties,
                                         Error* error,
                                         const ResultCallback& callback,
                                         int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary properties_dict =
      KeyValueStore::ConvertToVariantDictionary(properties);
  proxy_->ActivateManualAsync(
      properties_dict,
      base::Bind(&ModemModemCdmaProxy::OnOperationSuccess,
                 weak_factory_.GetWeakPtr(), callback, __func__),
      base::Bind(&ModemModemCdmaProxy::OnOperationFailure,
                 weak_factory_.GetWeakPtr(), callback, __func__),
      timeout);
}

void ModemModemCdmaProxy::ActivationStateChanged(
    uint32_t activation_state,
    uint32_t activation_error,
    const brillo::VariantDictionary& status_changes) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  if (activation_state_callback_.is_null()) {
    return;
  }
  KeyValueStore status_store =
      KeyValueStore::ConvertFromVariantDictionary(status_changes);
  activation_state_callback_.Run(activation_state, activation_error,
                                 status_store);
}

void ModemModemCdmaProxy::OnOperationSuccess(const ResultCallback& callback,
                                             const std::string& operation) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  callback.Run(Error());
}

void ModemModemCdmaProxy::OnOperationFailure(const ResultCallback& callback,
                                             const std::string& operation,
                                             brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(Error());
}

void ModemModemCdmaProxy::OnSignalConnected(const std::string& interface_name,
                                            const std::string& signal_name,
                                            bool success) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace mm1
}  // namespace shill
