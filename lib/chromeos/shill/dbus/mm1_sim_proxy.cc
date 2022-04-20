// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_sim_proxy.h"

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

SimProxy::SimProxy(const scoped_refptr<dbus::Bus>& bus,
                   const RpcIdentifier& path,
                   const std::string& service)
    : proxy_(
          new org::freedesktop::ModemManager1::SimProxy(bus, service, path)) {}

SimProxy::~SimProxy() = default;

void SimProxy::SendPin(const std::string& pin,
                       Error* error,
                       const ResultCallback& callback,
                       int timeout) {
  // pin is intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->SendPinAsync(
      pin,
      base::Bind(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void SimProxy::SendPuk(const std::string& puk,
                       const std::string& pin,
                       Error* error,
                       const ResultCallback& callback,
                       int timeout) {
  // pin and puk are intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->SendPukAsync(
      puk, pin,
      base::Bind(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void SimProxy::EnablePin(const std::string& pin,
                         const bool enabled,
                         Error* error,
                         const ResultCallback& callback,
                         int timeout) {
  // pin is intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << enabled;
  proxy_->EnablePinAsync(
      pin, enabled,
      base::Bind(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void SimProxy::ChangePin(const std::string& old_pin,
                         const std::string& new_pin,
                         Error* error,
                         const ResultCallback& callback,
                         int timeout) {
  // old_pin and new_pin are intentionally not logged.
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->ChangePinAsync(
      old_pin, new_pin,
      base::Bind(&SimProxy::OnOperationSuccess, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      base::Bind(&SimProxy::OnOperationFailure, weak_factory_.GetWeakPtr(),
                 callback, __func__),
      timeout);
}

void SimProxy::OnOperationSuccess(const ResultCallback& callback,
                                  const std::string& operation) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  callback.Run(Error());
}

void SimProxy::OnOperationFailure(const ResultCallback& callback,
                                  const std::string& operation,
                                  brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << operation;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(error);
}

}  // namespace mm1
}  // namespace shill
