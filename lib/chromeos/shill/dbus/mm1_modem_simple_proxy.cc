// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/mm1_modem_simple_proxy.h"

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

ModemSimpleProxy::ModemSimpleProxy(const scoped_refptr<dbus::Bus>& bus,
                                   const RpcIdentifier& path,
                                   const std::string& service)
    : proxy_(new org::freedesktop::ModemManager1::Modem::SimpleProxy(
          bus, service, path)) {}

ModemSimpleProxy::~ModemSimpleProxy() = default;

void ModemSimpleProxy::Connect(const KeyValueStore& properties,
                               const RpcIdentifierCallback& callback,
                               int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  brillo::VariantDictionary properties_dict =
      KeyValueStore::ConvertToVariantDictionary(properties);
  proxy_->ConnectAsync(properties_dict,
                       base::Bind(&ModemSimpleProxy::OnConnectSuccess,
                                  weak_factory_.GetWeakPtr(), callback),
                       base::Bind(&ModemSimpleProxy::OnConnectFailure,
                                  weak_factory_.GetWeakPtr(), callback),
                       timeout);
}

void ModemSimpleProxy::Disconnect(const RpcIdentifier& bearer,
                                  const ResultCallback& callback,
                                  int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << bearer.value();
  proxy_->DisconnectAsync(dbus::ObjectPath(bearer),
                          base::Bind(&ModemSimpleProxy::OnDisconnectSuccess,
                                     weak_factory_.GetWeakPtr(), callback),
                          base::Bind(&ModemSimpleProxy::OnDisconnectFailure,
                                     weak_factory_.GetWeakPtr(), callback),
                          timeout);
}

void ModemSimpleProxy::GetStatus(const KeyValueStoreCallback& callback,
                                 int timeout) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  proxy_->GetStatusAsync(base::Bind(&ModemSimpleProxy::OnGetStatusSuccess,
                                    weak_factory_.GetWeakPtr(), callback),
                         base::Bind(&ModemSimpleProxy::OnGetStatusFailure,
                                    weak_factory_.GetWeakPtr(), callback),
                         timeout);
}

void ModemSimpleProxy::OnConnectSuccess(const RpcIdentifierCallback& callback,
                                        const dbus::ObjectPath& path) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << ": " << path.value();
  callback.Run(path, Error());
}

void ModemSimpleProxy::OnConnectFailure(const RpcIdentifierCallback& callback,
                                        brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(RpcIdentifier(""), error);
}

void ModemSimpleProxy::OnDisconnectSuccess(const ResultCallback& callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  callback.Run(Error());
}

void ModemSimpleProxy::OnDisconnectFailure(const ResultCallback& callback,
                                           brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(error);
}

void ModemSimpleProxy::OnGetStatusSuccess(
    const KeyValueStoreCallback& callback,
    const brillo::VariantDictionary& status) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  KeyValueStore status_store =
      KeyValueStore::ConvertFromVariantDictionary(status);
  callback.Run(status_store, Error());
}

void ModemSimpleProxy::OnGetStatusFailure(const KeyValueStoreCallback& callback,
                                          brillo::Error* dbus_error) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(KeyValueStore(), error);
}

}  // namespace mm1
}  // namespace shill
