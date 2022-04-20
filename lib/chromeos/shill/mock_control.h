// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_CONTROL_H_
#define SHILL_MOCK_CONTROL_H_

#include <memory>
#include <string>

#include <base/callback.h>
#include <gmock/gmock.h>

#include "shill/control_interface.h"
#include "shill/network/dhcp_proxy_interface.h"
#include "shill/network/dhcpcd_listener_interface.h"
#include "shill/power_manager_proxy_interface.h"
#include "shill/upstart/upstart_proxy_interface.h"

#if !defined(DISABLE_CELLULAR)
#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/cellular/mm1_modem_location_proxy_interface.h"
#include "shill/cellular/mm1_modem_modem3gpp_profile_manager_proxy_interface.h"
#include "shill/cellular/mm1_modem_modem3gpp_proxy_interface.h"
#include "shill/cellular/mm1_modem_modemcdma_proxy_interface.h"
#include "shill/cellular/mm1_modem_proxy_interface.h"
#include "shill/cellular/mm1_modem_signal_proxy_interface.h"
#include "shill/cellular/mm1_modem_simple_proxy_interface.h"
#include "shill/cellular/mm1_sim_proxy_interface.h"
#include "shill/dbus/dbus_properties_proxy.h"
#endif  // DISABLE_CELLULAR

#if !defined(DISABLE_WIFI)
#include "shill/supplicant/supplicant_bss_proxy_interface.h"
#endif  // DISABLE_WIFI

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
#include "shill/supplicant/mock_supplicant_process_proxy.h"
#include "shill/supplicant/supplicant_interface_proxy_interface.h"
#include "shill/supplicant/supplicant_network_proxy_interface.h"
#include "shill/supplicant/supplicant_process_proxy_interface.h"
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X

namespace shill {
// An implementation of the Shill RPC-channel-interface-factory interface that
// returns nice mocks.
class MockControl : public ControlInterface {
 public:
  MockControl();
  MockControl(const MockControl&) = delete;
  MockControl& operator=(const MockControl&) = delete;

  ~MockControl() override;

  void RegisterManagerObject(
      Manager* manager,
      const base::Closure& registration_done_callback) override{};

  // Each of these can be called once.  Ownership of the appropriate
  // interface pointer is given up upon call.
  std::unique_ptr<DeviceAdaptorInterface> CreateDeviceAdaptor(
      Device* device) override;
  std::unique_ptr<IPConfigAdaptorInterface> CreateIPConfigAdaptor(
      IPConfig* config) override;
  std::unique_ptr<ManagerAdaptorInterface> CreateManagerAdaptor(
      Manager* manager) override;
  std::unique_ptr<ProfileAdaptorInterface> CreateProfileAdaptor(
      Profile* profile) override;
  std::unique_ptr<RpcTaskAdaptorInterface> CreateRpcTaskAdaptor(
      RpcTask* task) override;
  std::unique_ptr<ServiceAdaptorInterface> CreateServiceAdaptor(
      Service* service) override;
#ifndef DISABLE_VPN
  std::unique_ptr<ThirdPartyVpnAdaptorInterface> CreateThirdPartyVpnAdaptor(
      ThirdPartyVpnDriver* driver) override;
#endif

  MOCK_METHOD(std::unique_ptr<PowerManagerProxyInterface>,
              CreatePowerManagerProxy,
              (PowerManagerProxyDelegate*,
               const base::Closure&,
               const base::Closure&),
              (override));
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  std::unique_ptr<SupplicantProcessProxyInterface> CreateSupplicantProcessProxy(
      const base::Closure&, const base::Closure&) override;
  MOCK_METHOD(std::unique_ptr<SupplicantInterfaceProxyInterface>,
              CreateSupplicantInterfaceProxy,
              (SupplicantEventDelegateInterface*, const RpcIdentifier&),
              (override));
  MOCK_METHOD(std::unique_ptr<SupplicantNetworkProxyInterface>,
              CreateSupplicantNetworkProxy,
              (const RpcIdentifier&),
              (override));
  const base::Closure& supplicant_appear() const;
  const base::Closure& supplicant_vanish() const;
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X
#if !defined(DISABLE_WIFI)
  MOCK_METHOD(std::unique_ptr<SupplicantBSSProxyInterface>,
              CreateSupplicantBSSProxy,
              (WiFiEndpoint*, const RpcIdentifier&),
              (override));
#endif  // DISABLE_WIFI
  MOCK_METHOD(std::unique_ptr<DHCPCDListenerInterface>,
              CreateDHCPCDListener,
              (DHCPProvider*),
              (override));
  MOCK_METHOD(std::unique_ptr<DHCPProxyInterface>,
              CreateDHCPProxy,
              (const std::string&),
              (override));

  MOCK_METHOD(std::unique_ptr<UpstartProxyInterface>,
              CreateUpstartProxy,
              (),
              (override));

#if !defined(DISABLE_CELLULAR)
  MOCK_METHOD(std::unique_ptr<DBusPropertiesProxy>,
              CreateDBusPropertiesProxy,
              (const RpcIdentifier&, const std::string&),
              (override));

  MOCK_METHOD(std::unique_ptr<DBusObjectManagerProxyInterface>,
              CreateDBusObjectManagerProxy,
              (const RpcIdentifier&,
               const std::string&,
               const base::Closure&,
               const base::Closure&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemLocationProxyInterface>,
              CreateMM1ModemLocationProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemModem3gppProxyInterface>,
              CreateMM1ModemModem3gppProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>,
              CreateMM1ModemModem3gppProfileManagerProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemModemCdmaProxyInterface>,
              CreateMM1ModemModemCdmaProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemProxyInterface>,
              CreateMM1ModemProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemSignalProxyInterface>,
              CreateMM1ModemSignalProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::ModemSimpleProxyInterface>,
              CreateMM1ModemSimpleProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<mm1::SimProxyInterface>,
              CreateMM1SimProxy,
              (const RpcIdentifier&, const std::string&),
              (override));
#endif  // DISABLE_CELLULAR

 private:
  RpcIdentifier null_identifier_;

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  base::Closure supplicant_appear_;
  base::Closure supplicant_vanish_;
#endif  // DISABLE_WIFI || DISABLE_WIRED_8021X
};

}  // namespace shill

#endif  // SHILL_MOCK_CONTROL_H_
