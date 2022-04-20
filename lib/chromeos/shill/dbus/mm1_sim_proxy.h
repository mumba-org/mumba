// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_SIM_PROXY_H_
#define SHILL_DBUS_MM1_SIM_PROXY_H_

#include <memory>
#include <string>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_sim_proxy_interface.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Sim.
class SimProxy : public SimProxyInterface {
 public:
  // Constructs an org.freedesktop.ModemManager1.Sim DBus object
  // proxy at |path| owned by |service|.
  SimProxy(const scoped_refptr<dbus::Bus>& bus,
           const RpcIdentifier& path,
           const std::string& service);
  SimProxy(const SimProxy&) = delete;
  SimProxy& operator=(const SimProxy&) = delete;

  ~SimProxy() override;

  // Inherited methods from SimProxyInterface.
  void SendPin(const std::string& pin,
               Error* error,
               const ResultCallback& callback,
               int timeout) override;
  void SendPuk(const std::string& puk,
               const std::string& pin,
               Error* error,
               const ResultCallback& callback,
               int timeout) override;
  void EnablePin(const std::string& pin,
                 const bool enabled,
                 Error* error,
                 const ResultCallback& callback,
                 int timeout) override;
  void ChangePin(const std::string& old_pin,
                 const std::string& new_pin,
                 Error* error,
                 const ResultCallback& callback,
                 int timeout) override;

 private:
  // Callbacks for async method calls.
  void OnOperationSuccess(const ResultCallback& callback,
                          const std::string& operation);
  void OnOperationFailure(const ResultCallback& callback,
                          const std::string& operation,
                          brillo::Error* dbus_error);

  std::unique_ptr<org::freedesktop::ModemManager1::SimProxy> proxy_;

  base::WeakPtrFactory<SimProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_SIM_PROXY_H_
