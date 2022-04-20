// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_proxy.h"

#include <tuple>

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

ModemProxy::ModemProxy(const scoped_refptr<dbus::Bus>& bus,
                       const RpcIdentifier& path,
                       const std::string& service)
    : proxy_(
          new org::freedesktop::ModemManager1::ModemProxy(bus, service, path)) {
  // Register signal handlers.
  proxy_->RegisterStateChangedSignalHandler(
      base::Bind(&ModemProxy::StateChanged, weak_factory_.GetWeakPtr()),
      base::Bind(&ModemProxy::OnSignalConnected, weak_factory_.GetWeakPtr()));
}

ModemProxy::~ModemProxy() = default;

void ModemProxy::Enable(bool enable,
                        Error* error,
                        const ResultCallback& callback,
                        int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << enable;
  proxy_->EnableAsync(
      enable,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::CreateBearer(const KeyValueStore& properties,
                              Error* error,
                              const RpcIdentifierCallback& callback,
                              int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary properties_dict =
      KeyValueStore::ConvertToVariantDictionary(properties);
  proxy_->CreateBearerAsync(properties_dict,
                            base::Bind(&ModemProxy::OnCreateBearerSuccess,
                                       weak_factory_.GetWeakPtr(), callback),
                            base::Bind(&ModemProxy::OnCreateBearerFailure,
                                       weak_factory_.GetWeakPtr(), callback),
                            timeout);
}

void ModemProxy::DeleteBearer(const RpcIdentifier& bearer,
                              Error* error,
                              const ResultCallback& callback,
                              int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << bearer.value();
  proxy_->DeleteBearerAsync(
      bearer,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::Reset(Error* error,
                       const ResultCallback& callback,
                       int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->ResetAsync(base::Bind(&ModemProxy::OnOperationSuccess,
                                weak_factory_.GetWeakPtr(), callback, __func__),
                     base::Bind(&ModemProxy::OnOperationFailure,
                                weak_factory_.GetWeakPtr(), callback, __func__),
                     timeout);
}

void ModemProxy::FactoryReset(const std::string& code,
                              Error* error,
                              const ResultCallback& callback,
                              int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->FactoryResetAsync(
      code,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::SetCurrentCapabilities(uint32_t capabilities,
                                        Error* error,
                                        const ResultCallback& callback,
                                        int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << capabilities;
  proxy_->SetCurrentCapabilitiesAsync(
      capabilities,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::SetCurrentModes(uint32_t allowed_modes,
                                 uint32_t preferred_mode,
                                 Error* error,
                                 const ResultCallback& callback,
                                 int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": " << allowed_modes << " " << preferred_mode;
  std::tuple<uint32_t, uint32_t> modes{allowed_modes, preferred_mode};
  proxy_->SetCurrentModesAsync(
      modes,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::SetCurrentBands(const std::vector<uint32_t>& bands,
                                 Error* error,
                                 const ResultCallback& callback,
                                 int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->SetCurrentBandsAsync(
      bands,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::SetPrimarySimSlot(uint32_t slot,
                                   const ResultCallback& callback,
                                   int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << slot;
  proxy_->SetPrimarySimSlotAsync(
      slot,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::Command(const std::string& cmd,
                         uint32_t user_timeout,
                         Error* error,
                         const StringCallback& callback,
                         int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << cmd;
  proxy_->CommandAsync(cmd, user_timeout,
                       base::Bind(&ModemProxy::OnCommandSuccess,
                                  weak_factory_.GetWeakPtr(), callback),
                       base::Bind(&ModemProxy::OnCommandFailure,
                                  weak_factory_.GetWeakPtr(), callback),
                       timeout);
}

void ModemProxy::SetPowerState(uint32_t power_state,
                               Error* error,
                               const ResultCallback& callback,
                               int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << power_state;
  proxy_->SetPowerStateAsync(
      power_state,
      base::Bind(&ModemProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&ModemProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void ModemProxy::StateChanged(int32_t old, int32_t _new, uint32_t reason) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  if (state_changed_callback_.is_null()) {
    return;
  }
  state_changed_callback_.Run(old, _new, reason);
}

void ModemProxy::OnCreateBearerSuccess(const RpcIdentifierCallback& callback,
                                       const dbus::ObjectPath& path) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << path.value();
  callback.Run(path, Error());
}

void ModemProxy::OnCreateBearerFailure(const RpcIdentifierCallback& callback,
                                       brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(RpcIdentifier(""), error);
}

void ModemProxy::OnCommandSuccess(const StringCallback& callback,
                                  const std::string& response) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << response;
  callback.Run(response, Error());
}

void ModemProxy::OnCommandFailure(const StringCallback& callback,
                                  brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run("", error);
}

void ModemProxy::OnOperationSuccess(const ResultCallback& callback,
                                    const std::string& operation) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  callback.Run(Error());
}

void ModemProxy::OnOperationFailure(const ResultCallback& callback,
                                    const std::string& operation,
                                    brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(error);
}

void ModemProxy::OnSignalConnected(const std::string& interface_name,
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
