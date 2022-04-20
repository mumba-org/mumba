// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_proxy_interface.h"
#include "shill/store/key_value_store.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.
class ModemProxy : public ModemProxyInterface {
 public:
  // Constructs a org.freedesktop.ModemManager1.Modem DBus object
  // proxy at |path| owned by |service|.
  ModemProxy(const scoped_refptr<dbus::Bus>& bus,
             const RpcIdentifier& path,
             const std::string& service);
  ModemProxy(const ModemProxy&) = delete;
  ModemProxy& operator=(const ModemProxy&) = delete;

  ~ModemProxy() override;

  // Inherited methods from ModemProxyInterface.
  void Enable(bool enable,
              Error* error,
              const ResultCallback& callback,
              int timeout) override;
  void CreateBearer(const KeyValueStore& properties,
                    Error* error,
                    const RpcIdentifierCallback& callback,
                    int timeout) override;
  void DeleteBearer(const RpcIdentifier& bearer,
                    Error* error,
                    const ResultCallback& callback,
                    int timeout) override;
  void Reset(Error* error,
             const ResultCallback& callback,
             int timeout) override;
  void FactoryReset(const std::string& code,
                    Error* error,
                    const ResultCallback& callback,
                    int timeout) override;
  void SetCurrentCapabilities(uint32_t capabilities,
                              Error* error,
                              const ResultCallback& callback,
                              int timeout) override;
  void SetCurrentModes(uint32_t allowed_modes,
                       uint32_t preferred_mode,
                       Error* error,
                       const ResultCallback& callback,
                       int timeout) override;
  void SetCurrentBands(const std::vector<uint32_t>& bands,
                       Error* error,
                       const ResultCallback& callback,
                       int timeout) override;
  void SetPrimarySimSlot(uint32_t slot,
                         const ResultCallback& callback,
                         int timeout) override;
  void Command(const std::string& cmd,
               uint32_t user_timeout,
               Error* error,
               const StringCallback& callback,
               int timeout) override;
  void SetPowerState(uint32_t power_state,
                     Error* error,
                     const ResultCallback& callback,
                     int timeout) override;

  void set_state_changed_callback(
      const ModemStateChangedSignalCallback& callback) override {
    state_changed_callback_ = callback;
  }

 private:
  // Signal handler.
  void StateChanged(int32_t old, int32_t _new, uint32_t reason);

  // Callbacks for CreateBearer async call.
  void OnCreateBearerSuccess(const RpcIdentifierCallback& callback,
                             const dbus::ObjectPath& path);
  void OnCreateBearerFailure(const RpcIdentifierCallback& callback,
                             brillo::Error* dbus_error);

  // Callbacks for Command async call.
  void OnCommandSuccess(const StringCallback& callback,
                        const std::string& response);
  void OnCommandFailure(const StringCallback& callback,
                        brillo::Error* dbus_error);

  // Callbacks for various async calls that uses ResultCallback.
  void OnOperationSuccess(const ResultCallback& callback,
                          const std::string& operation);
  void OnOperationFailure(const ResultCallback& callback,
                          const std::string& operation,
                          brillo::Error* dbus_error);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  ModemStateChangedSignalCallback state_changed_callback_;

  std::unique_ptr<org::freedesktop::ModemManager1::ModemProxy> proxy_;

  base::WeakPtrFactory<ModemProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_PROXY_H_
