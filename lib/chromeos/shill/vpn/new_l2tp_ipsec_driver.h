// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_NEW_L2TP_IPSEC_DRIVER_H_
#define SHILL_VPN_NEW_L2TP_IPSEC_DRIVER_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>

#include "shill/manager.h"
#include "shill/mockable.h"
#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/l2tp_connection.h"
#include "shill/vpn/vpn_connection.h"
#include "shill/vpn/vpn_driver.h"

namespace shill {

// TODO(b/165170125): Once the current L2TPIPsecDriver is removed, rename this
// class to L2TPIPsecDriver.
class NewL2TPIPsecDriver : public VPNDriver {
 public:
  NewL2TPIPsecDriver(Manager* manager, ProcessManager* process_manager);
  NewL2TPIPsecDriver(const NewL2TPIPsecDriver&) = delete;
  NewL2TPIPsecDriver& operator=(const NewL2TPIPsecDriver&) = delete;
  ~NewL2TPIPsecDriver() override;

  // Inherited from VPNDriver.
  base::TimeDelta ConnectAsync(EventHandler* handler) override;
  void Disconnect() override;
  IPConfig::Properties GetIPProperties() const override;
  std::string GetProviderType() const override;
  void OnConnectTimeout() override;

  // Disconnects from the VPN service before suspend or when the current default
  // physical service becomes unavailable. The reconnection behavior relies on
  // whether the user sets "Automatically connect to this network".
  void OnBeforeSuspend(const ResultCallback& callback) override;
  void OnDefaultPhysicalServiceEvent(
      DefaultPhysicalServiceEvent event) override;

 private:
  friend class NewL2TPIPsecDriverUnderTest;

  static const VPNDriver::Property kProperties[];

  void NotifyServiceOfFailure(Service::ConnectFailure failure);

  void StartIPsecConnection();

  // Isolates the creation of VPNConnections for the ease of unit tests. These
  // two functions are static, but we do not declare them as const also for the
  // ease of unit tests.
  mockable std::unique_ptr<VPNConnection> CreateIPsecConnection(
      std::unique_ptr<IPsecConnection::Config> config,
      std::unique_ptr<VPNConnection::Callbacks> callbacks,
      std::unique_ptr<VPNConnection> l2tp_connection,
      DeviceInfo* device_info,
      EventDispatcher* dispatcher,
      ProcessManager* process_manager);
  mockable std::unique_ptr<VPNConnection> CreateL2TPConnection(
      std::unique_ptr<L2TPConnection::Config> config,
      ControlInterface* control_interface,
      DeviceInfo* device_info,
      EventDispatcher* dispatcher,
      ProcessManager* process_manager);

  // Callbacks from IPsecConnection.
  void OnIPsecConnected(const std::string& link_name,
                        int interface_index,
                        const IPConfig::Properties& ip_properties);
  void OnIPsecFailure(Service::ConnectFailure failure);
  void OnIPsecStopped();

  // Inherit from VPNDriver to add custom properties.
  KeyValueStore GetProvider(Error* error) override;

  void ReportConnectionMetrics();

  EventHandler* event_handler_ = nullptr;
  std::unique_ptr<VPNConnection> ipsec_connection_;
  IPConfig::Properties ip_properties_;

  base::WeakPtrFactory<NewL2TPIPsecDriver> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_NEW_L2TP_IPSEC_DRIVER_H_
