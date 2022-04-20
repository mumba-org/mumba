// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_signal_proxy.h"

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

ModemSignalProxy::ModemSignalProxy(const scoped_refptr<dbus::Bus>& bus,
                                   const RpcIdentifier& path,
                                   const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::SignalProxy(
          bus, service, path)) {}

ModemSignalProxy::~ModemSignalProxy() = default;

void ModemSignalProxy::Setup(const int rate,
                             Error* /*error*/,
                             const ResultCallback& callback,
                             int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << rate;
  proxy_->SetupAsync(rate,
                     base::Bind(&ModemSignalProxy::OnSetupSuccess,
                                weak_factory_.GetWeakPtr(), callback),
                     base::Bind(&ModemSignalProxy::OnSetupFailure,
                                weak_factory_.GetWeakPtr(), callback),
                     timeout);
}

void ModemSignalProxy::OnSetupSuccess(const ResultCallback& callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  callback.Run(Error());
}

void ModemSignalProxy::OnSetupFailure(const ResultCallback& callback,
                                      brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(error);
}

}  // namespace mm1
}  // namespace shill
