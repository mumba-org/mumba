// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_CAPABILITY_CDMA_H_
#define SHILL_CELLULAR_CELLULAR_CAPABILITY_CDMA_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_capability_3gpp.h"
#include "shill/cellular/mm1_modem_modemcdma_proxy_interface.h"

namespace shill {

class CellularCapabilityCdma : public CellularCapability3gpp {
 public:
  CellularCapabilityCdma(Cellular* cellular,
                         ControlInterface* control_interface,
                         Metrics* metrics,
                         PendingActivationStore* pending_activation_store);
  CellularCapabilityCdma(const CellularCapabilityCdma&) = delete;
  CellularCapabilityCdma& operator=(const CellularCapabilityCdma&) = delete;

  ~CellularCapabilityCdma() override;

  // Returns true if the service is activated.
  bool IsActivated() const;

  // Inherited from CellularCapability.
  void OnPropertiesChanged(const std::string& interface,
                           const KeyValueStore& changed_properties) override;
  bool IsServiceActivationRequired() const override;
  bool IsActivating() const override;
  void CompleteActivation(Error* error) override;
  bool IsRegistered() const override;
  void SetUnregistered(bool searching) override;
  void OnServiceCreated() override;
  std::string GetRoamingStateString() const override;

  void RegisterOnNetwork(const std::string& network_id,
                         Error* error,
                         const ResultCallback& callback) override;
  void RequirePin(const std::string& pin,
                  bool require,
                  Error* error,
                  const ResultCallback& callback) override;
  void EnterPin(const std::string& pin,
                Error* error,
                const ResultCallback& callback) override;
  void UnblockPin(const std::string& unblock_code,
                  const std::string& pin,
                  Error* error,
                  const ResultCallback& callback) override;
  void ChangePin(const std::string& old_pin,
                 const std::string& new_pin,
                 Error* error,
                 const ResultCallback& callback) override;
  void Reset(Error* error, const ResultCallback& callback) override;
  void Scan(Error* error, const ResultStringmapsCallback& callback) override;

  void GetProperties() override;

 protected:
  // Inherited from CellularCapability3gpp.
  void SetupConnectProperties(KeyValueStore* properties) override;
  void InitProxies() override;
  void ReleaseProxies() override;
  void UpdateServiceOLP() override;

  // Post-payment activation handlers.
  void UpdatePendingActivationState() override;

 private:
  friend class CellularCapabilityCdmaTest;
  FRIEND_TEST(CellularCapabilityCdmaDispatcherTest,
              UpdatePendingActivationState);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, ActivateAutomatic);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, IsActivating);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, IsRegistered);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, IsServiceActivationRequired);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, OnCdmaRegistrationChanged);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, PropertiesChanged);
  FRIEND_TEST(CellularCapabilityCdmaMainTest, UpdateServiceOLP);
  FRIEND_TEST(CellularCapabilityCdmaMainTest,
              UpdateServiceActivationStateProperty);

  // CDMA property change handlers
  void OnModemCdmaPropertiesChanged(const KeyValueStore& properties);
  void OnCdmaRegistrationChanged(MMModemCdmaRegistrationState state_1x,
                                 MMModemCdmaRegistrationState state_evdo,
                                 uint32_t sid,
                                 uint32_t nid);

  // CDMA activation handlers
  void ActivateAutomatic();
  void OnActivationStateChangedSignal(uint32_t activation_state,
                                      uint32_t activation_error,
                                      const KeyValueStore& status_changes);
  void OnActivateReply(const ResultCallback& callback, const Error& error);
  void HandleNewActivationStatus(uint32_t error);

  void UpdateServiceActivationStateProperty();

  std::unique_ptr<mm1::ModemModemCdmaProxyInterface> modem_cdma_proxy_;

  // CDMA ActivationState property.
  MMModemCdmaActivationState activation_state_;

  MMModemCdmaRegistrationState cdma_1x_registration_state_;
  MMModemCdmaRegistrationState cdma_evdo_registration_state_;

  uint32_t nid_;
  uint32_t sid_;

  // TODO(armansito): Should probably call this |weak_ptr_factory_| after
  // 3gpp refactor
  base::WeakPtrFactory<CellularCapabilityCdma> weak_cdma_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_CAPABILITY_CDMA_H_
