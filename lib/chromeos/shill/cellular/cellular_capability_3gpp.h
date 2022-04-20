// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_CAPABILITY_3GPP_H_
#define SHILL_CELLULAR_CELLULAR_CAPABILITY_3GPP_H_

#include <deque>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <ModemManager/ModemManager.h>
#include <base/containers/flat_map.h>
#include <base/containers/flat_set.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_bearer.h"
#include "shill/cellular/cellular_capability.h"
#include "shill/cellular/mm1_modem_location_proxy_interface.h"
#include "shill/cellular/mm1_modem_modem3gpp_profile_manager_proxy_interface.h"
#include "shill/cellular/mm1_modem_modem3gpp_proxy_interface.h"
#include "shill/cellular/mm1_modem_proxy_interface.h"
#include "shill/cellular/mm1_modem_signal_proxy_interface.h"
#include "shill/cellular/mm1_modem_simple_proxy_interface.h"
#include "shill/cellular/mm1_sim_proxy_interface.h"
#include "shill/cellular/subscription_state.h"
#include "shill/data_types.h"
#include "shill/store/key_value_store.h"

namespace shill {

// CellularCapability3gpp handles modems using the
// org.freedesktop.ModemManager1 DBUS interface.  This class is used for
// all types of modems, i.e. CDMA, GSM, and LTE modems.
class CellularCapability3gpp : public CellularCapability {
 public:
  using ScanResults = std::vector<KeyValueStore>;
  using ScanResult = KeyValueStore;
  using LockRetryData = std::map<uint32_t, uint32_t>;
  using SignalQuality = std::tuple<uint32_t, bool>;
  using ModesData = std::tuple<uint32_t, uint32_t>;
  using SupportedModes = std::vector<ModesData>;
  using PcoList = std::vector<std::tuple<uint32_t, bool, std::vector<uint8_t>>>;
  using Profiles = std::vector<brillo::VariantDictionary>;

  // Constants used in connect method call.  Make available to test matchers.
  static const char kConnectApn[];
  static const char kConnectUser[];
  static const char kConnectPassword[];
  static const char kConnectAllowedAuth[];
  static const char kConnectAllowRoaming[];
  static const char kConnectIpType[];

  using SimProperties = Cellular::SimProperties;

  CellularCapability3gpp(Cellular* cellular,
                         ControlInterface* control_interface,
                         Metrics* metrics,
                         PendingActivationStore* pending_activation_store);
  CellularCapability3gpp(const CellularCapability3gpp&) = delete;
  CellularCapability3gpp& operator=(const CellularCapability3gpp&) = delete;

  ~CellularCapability3gpp() override;

  // Inherited from CellularCapability.
  std::string GetTypeString() const override;
  void SetInitialProperties(const InterfaceToProperties& properties) override;

  // Checks the modem state.  If the state is kModemStateDisabled, then the
  // modem is enabled.  Otherwise, the enable command is buffered until the
  // modem becomes disabled.  ModemManager rejects the enable command if the
  // modem is not disabled, for example, if it is initializing instead.
  void StartModem(Error* error, const ResultCallback& callback) override;
  void SetModemToLowPowerModeOnModemStop(bool set_low_power) override;
  void StopModem(Error* error, const ResultCallback& callback) override;
  void Reset(Error* error, const ResultCallback& callback) override;
  bool IsServiceActivationRequired() const override;
  bool IsActivating() const override;
  void CompleteActivation(Error* error) override;
  void Scan(Error* error, const ResultStringmapsCallback& callback) override;
  void SetInitialEpsBearer(const KeyValueStore& properties,
                           Error* error,
                           const ResultCallback& callback) override;
  void RegisterOnNetwork(const std::string& network_id,
                         Error* error,
                         const ResultCallback& callback) override;
  bool IsRegistered() const override;
  void SetUnregistered(bool searching) override;
  void OnServiceCreated() override;
  uint32_t GetActiveAccessTechnologies() const override;
  std::string GetNetworkTechnologyString() const override;
  std::string GetRoamingStateString() const override;
  void Connect(const ResultCallback& callback) override;
  void Disconnect(const ResultCallback& callback) override;
  CellularBearer* GetActiveBearer() const override;
  const std::vector<MobileOperatorInfo::MobileAPN>& GetProfiles()
      const override;
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
  KeyValueStore SimLockStatusToProperty(Error* error) override;
  bool SetPrimarySimSlotForIccid(const std::string& iccid) override;

  virtual void GetProperties();

  // Property change handler. Overridden by the Cdma impl to handle MODEMCDMA.
  virtual void OnPropertiesChanged(const std::string& interface,
                                   const KeyValueStore& changed_properties);

  // Location proxy methods
  void SetupLocation(uint32_t sources,
                     bool signal_location,
                     const ResultCallback& callback) override;

  void GetLocation(const StringCallback& callback) override;

  void SetupSignal(uint32_t rate, const ResultCallback& callback) override;

  // Used to encapsulate bounds for rssi/rsrp
  struct SignalQualityBounds {
    const double min_threshold;
    const double max_threshold;

    // Convert signal_quality to a percentage between 0 and 100
    // If signal_quality < min_threshold, clamp to 0 %
    // If signal_quality > max_threshold, clamp to 100 %
    double GetAsPercentage(double signal_quality) const;
  };

  bool IsLocationUpdateSupported() const override;

  void SetDBusPropertiesProxyForTesting(
      std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy);
  void FillConnectPropertyMapForTesting(KeyValueStore* properties);

  uint32_t access_technologies_for_testing() const {
    return access_technologies_;
  }
  const RpcIdentifier& sim_path_for_testing() const { return sim_path_; }
  const base::flat_map<RpcIdentifier, SimProperties>&
  sim_properties_for_testing() const {
    return sim_properties_;
  }
  void set_sim_properties_for_testing(
      const base::flat_map<RpcIdentifier, SimProperties>& sim_properties) {
    sim_properties_ = sim_properties;
  }

  // Constants used in scan results.  Make available to unit tests.
  static const char kStatusProperty[];
  static const char kOperatorLongProperty[];
  static const char kOperatorShortProperty[];
  static const char kOperatorCodeProperty[];
  static const char kOperatorAccessTechnologyProperty[];

  static const SignalQualityBounds kRssiBounds;
  static const SignalQualityBounds kRsrpBounds;
  static const SignalQualityBounds kRscpBounds;

  static const char kRsrpProperty[];
  static const char kRssiProperty[];
  static const char kRscpProperty[];

  static const int64_t kEnterPinTimeoutMilliseconds;
  static const int64_t kRegistrationDroppedUpdateTimeoutMilliseconds;
  static constexpr base::TimeDelta kSetNextAttachApnTimeout =
      base::Milliseconds(12500);
  static const int kSetPowerStateTimeoutMilliseconds;

  static const int kUnknownLockRetriesLeft;

  // Root path. The SIM path is reported by ModemManager to be the root path
  // when no SIM is present.
  static const RpcIdentifier kRootPath;

 protected:
  virtual void SetupConnectProperties(KeyValueStore* properties);
  virtual void InitProxies();
  virtual void ReleaseProxies();

  // Updates the online payment portal information, if any, for the cellular
  // provider.
  void UpdateServiceOLP() override;

  // Post-payment activation handlers.
  virtual void UpdatePendingActivationState();

  // Returns the operator-specific form of |mdn|, which is passed to the online
  // payment portal of a cellular operator.
  std::string GetMdnForOLP(const MobileOperatorInfo* operator_info) const;

 private:
  friend class CellularTest;
  friend class CellularCapability3gppTest;
  friend class CellularCapabilityCdmaTest;
  friend class CellularServiceProviderTest;
  // CellularCapability3gppTimerTest
  FRIEND_TEST(CellularCapabilityCdmaMainTest, PropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, GetMdnForOLP);
  FRIEND_TEST(CellularCapability3gppTest, GetTypeString);
  FRIEND_TEST(CellularCapability3gppTest, IsMdnValid);
  FRIEND_TEST(CellularCapability3gppTest, IsRegistered);
  FRIEND_TEST(CellularCapability3gppTest, IsServiceActivationRequired);
  FRIEND_TEST(CellularCapability3gppTest, IsValidSimPath);
  FRIEND_TEST(CellularCapability3gppTest, NormalizeMdn);
  FRIEND_TEST(CellularCapability3gppTest, OnLockRetriesChanged);
  FRIEND_TEST(CellularCapability3gppTest, OnLockTypeChanged);
  FRIEND_TEST(CellularCapability3gppTest, OnModemCurrentCapabilitiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, OnSimLockPropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, PropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, SignalPropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, Reset);
  FRIEND_TEST(CellularCapability3gppTest, SetInitialEpsBearer);
  FRIEND_TEST(CellularCapability3gppTest, SimLockStatusChanged);
  FRIEND_TEST(CellularCapability3gppTest, SimLockStatusToProperty);
  FRIEND_TEST(CellularCapability3gppTest, SimPathChanged);
  FRIEND_TEST(CellularCapability3gppTest, SimPropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, StartModemInWrongState);
  FRIEND_TEST(CellularCapability3gppTest, StartModemWithDeferredEnableFailure);
  FRIEND_TEST(CellularCapability3gppTest, UpdateActiveBearer);
  FRIEND_TEST(CellularCapability3gppTest, UpdatePendingActivationState);
  FRIEND_TEST(CellularCapability3gppTest, UpdateRegistrationState);
  FRIEND_TEST(CellularCapability3gppTest,
              UpdateRegistrationStateModemNotConnected);
  FRIEND_TEST(CellularCapability3gppTest, UpdateServiceActivationState);
  FRIEND_TEST(CellularCapability3gppTest, UpdateServiceOLP);
  FRIEND_TEST(CellularCapability3gppTimerTest, CompleteActivation);
  // CellularTest
  FRIEND_TEST(CellularTest, ModemStateChangeLostRegistration);

  // SimLockStatus represents the fields in the Cellular.SIMLockStatus
  // DBUS property of the shill device.
  struct SimLockStatus {
    SimLockStatus()
        : enabled(false), lock_type(MM_MODEM_LOCK_UNKNOWN), retries_left(0) {}

    bool enabled;
    MMModemLock lock_type;
    int32_t retries_left;
  };

  // Methods used in starting a modem
  void EnableModemCompleted(const ResultCallback& callback, const Error& error);

  // Methods used in stopping a modem
  void Stop_Completed(const ResultCallback& callback, const Error& error);
  void Stop_Disable(const ResultCallback& callback);
  void Stop_DisableCompleted(const ResultCallback& callback,
                             const Error& error);
  void Stop_PowerDown(const ResultCallback& callback,
                      const Error& stop_disable_error);
  void Stop_PowerDownCompleted(const ResultCallback& callback,
                               const Error* stop_disable_error,
                               const Error& error);

  void Register(const ResultCallback& callback);

  // Updates |active_bearer_| to match the currently active bearer.
  void UpdateActiveBearer();

  Stringmap ParseScanResult(const ScanResult& result);

  void SetRoamingProperties(KeyValueStore* properties);
  bool SetApnProperties(const Stringmap& apn_info, KeyValueStore* properties);

  void SetNextAttachApn();
  void FillInitialEpsBearerPropertyMap(KeyValueStore* properties);

  // Returns true if a connect error should be retried.  This function
  // abstracts modem specific behavior for modems which do a lousy job
  // of returning specific errors on connect failures.
  bool RetriableConnectError(const Error& error) const;

  // Signal callbacks
  void OnModemStateChangedSignal(int32_t old_state,
                                 int32_t new_state,
                                 uint32_t reason);

  // Profile manager signal handlers and callbacks
  void OnProfilesListReply(const ResultCallback& callback,
                           const Profiles& results,
                           const Error& error);
  void OnModem3gppProfileManagerUpdatedSignal();

  // Property Change notification handlers
  void OnModemPropertiesChanged(const KeyValueStore& properties);

  void OnModemCurrentCapabilitiesChanged(uint32_t current_capabilities);
  void OnMdnChanged(const std::string& mdn);
  void OnModemStateChanged(Cellular::ModemState state);
  void OnAccessTechnologiesChanged(uint32_t access_technologies);
  void OnBearersChanged(const RpcIdentifiers& bearers);
  void OnLockRetriesChanged(const LockRetryData& lock_retries);
  void OnLockTypeChanged(MMModemLock unlock_required);
  void OnSimLockStatusChanged();

  // Returns false if the MDN is empty or if the MDN consists of all 0s.
  bool IsMdnValid() const;

  // 3GPP property change handlers
  void OnModem3gppPropertiesChanged(const KeyValueStore& properties);
  void OnProfilesChanged(const Profiles& profiles);
  void On3gppRegistrationChanged(MMModem3gppRegistrationState state,
                                 const std::string& operator_code,
                                 const std::string& operator_name);
  void Handle3gppRegistrationChange(MMModem3gppRegistrationState updated_state,
                                    const std::string& updated_operator_code,
                                    const std::string& updated_operator_name);
  void OnSubscriptionStateChanged(SubscriptionState updated_subscription_state);
  void OnFacilityLocksChanged(uint32_t locks);
  void OnPcoChanged(const PcoList& pco_list);
  void OnModemSignalPropertiesChanged(const KeyValueStore& props);

  // SIM property change handlers
  void RequestSimProperties(size_t slot, RpcIdentifier sim_path);
  void OnGetSimProperties(
      size_t slot,
      RpcIdentifier sim_path,
      std::unique_ptr<DBusPropertiesProxy> sim_properties_proxy,
      const KeyValueStore& properties);

  // Connect helpers and callbacks
  void CallConnect(const KeyValueStore& properties,
                   const ResultCallback& callback);
  void OnConnectReply(const ResultCallback& callback,
                      const RpcIdentifier& bearer,
                      const Error& error);
  bool ConnectToNextApn(const ResultCallback& callback);

  // Method callbacks
  void OnRegisterReply(const ResultCallback& callback, const Error& error);
  void OnResetReply(const ResultCallback& callback, const Error& error);
  void OnScanReply(const ResultStringmapsCallback& callback,
                   const ScanResults& results,
                   const Error& error);
  void OnSetupLocationReply(const Error& error);
  void OnGetLocationReply(const StringCallback& callback,
                          const std::map<uint32_t, brillo::Any>& results,
                          const Error& error);
  void OnSetupSignalReply(const Error& error);
  void OnSetInitialEpsBearerReply(const Error& error);

  // Returns the normalized version of |mdn| by keeping only digits in |mdn|
  // and removing other non-digit characters.
  std::string NormalizeMdn(const std::string& mdn) const;

  // Returns true, if |sim_path| constitutes a valid SIM path. Currently, a
  // path is accepted to be valid, as long as it is not equal to one of ""
  // and "/".
  bool IsValidSimPath(const RpcIdentifier& sim_path) const;

  void UpdateSims();
  void OnAllSimPropertiesReceived();
  void SetPrimarySimSlot(size_t slot);

  // Post-payment activation handlers.
  void ResetAfterActivation();
  void UpdateServiceActivationState();
  void OnResetAfterActivationReply(const Error& error);

  bool proxies_initialized_ = false;
  std::unique_ptr<mm1::ModemModem3gppProxyInterface> modem_3gpp_proxy_;
  std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
      modem_3gpp_profile_manager_proxy_;
  std::unique_ptr<mm1::ModemProxyInterface> modem_proxy_;
  std::unique_ptr<mm1::ModemSimpleProxyInterface> modem_simple_proxy_;
  std::unique_ptr<mm1::ModemSignalProxyInterface> modem_signal_proxy_;
  std::unique_ptr<mm1::SimProxyInterface> sim_proxy_;
  std::unique_ptr<mm1::ModemLocationProxyInterface> modem_location_proxy_;
  std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy_;

  // Used to enrich information about the network operator in |ParseScanResult|.
  // TODO(pprabhu) Instead instantiate a local |MobileOperatorInfo| instance
  // once the context has been separated out. (crbug.com/363874)
  std::unique_ptr<MobileOperatorInfo> mobile_operator_info_;

  MMModem3gppRegistrationState registration_state_ =
      MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;

  // Bits based on MMModemCapabilities
  // Technologies supported without a reload
  uint32_t current_capabilities_ = MM_MODEM_CAPABILITY_NONE;
  // Bits based on MMModemAccessTechnology
  uint32_t access_technologies_ = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;

  Stringmap serving_operator_;
  std::string desired_network_;

  // Properties.
  std::deque<Stringmap> apn_try_list_;
  std::deque<Stringmap> attach_apn_try_list_;
  // For attach APN, we don't really know if the APN is good or not, we only
  // know if ModemManager used the provided attach APN or not.
  Stringmap last_attach_apn_;
  bool resetting_ = false;
  SimLockStatus sim_lock_status_;
  SubscriptionState subscription_state_ = SubscriptionState::kUnknown;
  std::unique_ptr<CellularBearer> active_bearer_;
  RpcIdentifiers bearer_paths_;
  bool reset_done_ = false;
  std::vector<MobileOperatorInfo::MobileAPN> profiles_;
  bool set_modem_to_low_power_mode_on_stop_ = true;

  // SIM properties
  RpcIdentifier sim_path_;
  uint32_t primary_sim_slot_ = 0u;
  RpcIdentifiers sim_slots_;
  base::flat_set<RpcIdentifier> pending_sim_requests_;
  base::flat_map<RpcIdentifier, SimProperties> sim_properties_;

  // Sometimes flaky cellular network causes the 3GPP registration state to
  // rapidly change from registered --> searching and back. Delay such updates
  // a little to smooth over temporary registration loss.
  base::CancelableClosure registration_dropped_update_callback_;
  int64_t registration_dropped_update_timeout_milliseconds_ =
      kRegistrationDroppedUpdateTimeoutMilliseconds;

  // If the service providers DB contains multiple possible attach APNs, shill
  // needs to try all of them until the UE is registered in the network.
  base::CancelableOnceClosure try_next_attach_apn_callback_;

  base::WeakPtrFactory<CellularCapability3gpp> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_CAPABILITY_3GPP_H_
