// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_location_proxy.h"

#include <memory>

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

ModemLocationProxy::ModemLocationProxy(const scoped_refptr<dbus::Bus>& bus,
                                       const RpcIdentifier& path,
                                       const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::LocationProxy(
          bus, service, path)) {}

ModemLocationProxy::~ModemLocationProxy() = default;

void ModemLocationProxy::Setup(uint32_t sources,
                               bool signal_location,
                               Error* error,
                               const ResultCallback& callback,
                               int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": " << sources << ", " << signal_location;
  proxy_->SetupAsync(sources, signal_location,
                     base::Bind(&ModemLocationProxy::OnSetupSuccess,
                                weak_factory_.GetWeakPtr(), callback),
                     base::Bind(&ModemLocationProxy::OnSetupFailure,
                                weak_factory_.GetWeakPtr(), callback),
                     timeout);
}

void ModemLocationProxy::GetLocation(Error* error,
                                     const BrilloAnyCallback& callback,
                                     int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->GetLocationAsync(base::Bind(&ModemLocationProxy::OnGetLocationSuccess,
                                      weak_factory_.GetWeakPtr(), callback),
                           base::Bind(&ModemLocationProxy::OnGetLocationFailure,
                                      weak_factory_.GetWeakPtr(), callback),
                           timeout);
}

void ModemLocationProxy::OnSetupSuccess(const ResultCallback& callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  callback.Run(Error());
}

void ModemLocationProxy::OnSetupFailure(const ResultCallback& callback,
                                        brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(error);
}

void ModemLocationProxy::OnGetLocationSuccess(
    const BrilloAnyCallback& callback,
    const std::map<uint32_t, brillo::Any>& results) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  callback.Run(results, Error());
}

void ModemLocationProxy::OnGetLocationFailure(const BrilloAnyCallback& callback,
                                              brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(std::map<uint32_t, brillo::Any>(), error);
}

}  // namespace mm1
}  // namespace shill
