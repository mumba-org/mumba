// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_MODEM3GPP_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_MODEM3GPP_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_modem3gpp_proxy_interface.h"
#include "shill/store/key_value_store.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.Modem3gpp.
class ModemModem3gppProxy : public ModemModem3gppProxyInterface {
 public:
  // Constructs an org.freedesktop.ModemManager1.Modem.Modem3gpp DBus
  // object proxy at |path| owned by |service|.
  ModemModem3gppProxy(const scoped_refptr<dbus::Bus>& bus,
                      const RpcIdentifier& path,
                      const std::string& service);
  ModemModem3gppProxy(const ModemModem3gppProxy&) = delete;
  ModemModem3gppProxy& operator=(const ModemModem3gppProxy&) = delete;

  ~ModemModem3gppProxy() override;
  // Inherited methods from ModemModem3gppProxyInterface.
  void Register(const std::string& operator_id,
                Error* error,
                const ResultCallback& callback,
                int timeout) override;
  void Scan(Error* error,
            const KeyValueStoresCallback& callback,
            int timeout) override;
  void SetInitialEpsBearerSettings(const KeyValueStore& properties,
                                   Error* error,
                                   const ResultCallback& callback,
                                   int timeout) override;

 private:
  // Callbacks for Register async call.
  void OnRegisterSuccess(const ResultCallback& callback);
  void OnRegisterFailure(const ResultCallback& callback,
                         brillo::Error* dbus_error);

  // Callbacks for Scan async call.
  void OnScanSuccess(const KeyValueStoresCallback& callback,
                     const std::vector<brillo::VariantDictionary>& results);
  void OnScanFailure(const KeyValueStoresCallback& callback,
                     brillo::Error* dbus_error);

  // Callbacks for SetInitialEpsBearerSettings async call.
  void OnSetInitialEpsBearerSettingsSuccess(const ResultCallback& callback);
  void OnSetInitialEpsBearerSettingsFailure(const ResultCallback& callback,
                                            brillo::Error* dbus_error);

  std::unique_ptr<org::freedesktop::ModemManager1::Modem::Modem3gppProxy>
      proxy_;

  base::WeakPtrFactory<ModemModem3gppProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_MODEM3GPP_PROXY_H_
