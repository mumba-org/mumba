// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_SIMPLE_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_SIMPLE_PROXY_H_

#include <memory>
#include <string>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_simple_proxy_interface.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.Simple.
class ModemSimpleProxy : public ModemSimpleProxyInterface {
 public:
  // Constructs a org.freedesktop.ModemManager1.Modem.Simple DBus
  // object proxy at |path| owned by |service|.
  ModemSimpleProxy(const scoped_refptr<dbus::Bus>& bus,
                   const RpcIdentifier& path,
                   const std::string& service);
  ModemSimpleProxy(const ModemSimpleProxy&) = delete;
  ModemSimpleProxy& operator=(const ModemSimpleProxy&) = delete;

  ~ModemSimpleProxy() override;

  // Inherited methods from SimpleProxyInterface.
  void Connect(const KeyValueStore& properties,
               const RpcIdentifierCallback& callback,
               int timeout) override;
  void Disconnect(const RpcIdentifier& bearer,
                  const ResultCallback& callback,
                  int timeout) override;
  void GetStatus(const KeyValueStoreCallback& callback, int timeout) override;

 private:
  // Callbacks for Connect async call.
  void OnConnectSuccess(const RpcIdentifierCallback& callback,
                        const dbus::ObjectPath& path);
  void OnConnectFailure(const RpcIdentifierCallback& callback,
                        brillo::Error* error);

  // Callbacks for Disconnect async call.
  void OnDisconnectSuccess(const ResultCallback& callback);
  void OnDisconnectFailure(const ResultCallback& callbac,
                           brillo::Error* dbus_error);

  // Callbacks for GetStatus async call.
  void OnGetStatusSuccess(const KeyValueStoreCallback& callback,
                          const brillo::VariantDictionary& status);
  void OnGetStatusFailure(const KeyValueStoreCallback& callback,
                          brillo::Error* error);

  std::unique_ptr<org::freedesktop::ModemManager1::Modem::SimpleProxy> proxy_;

  base::WeakPtrFactory<ModemSimpleProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_SIMPLE_PROXY_H_
