// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_H_
#define SHILL_CELLULAR_CELLULAR_H_

#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/cellular/mobile_operator_info.h"
#include "shill/device.h"
#include "shill/device_id.h"
#include "shill/event_dispatcher.h"
#include "shill/metrics.h"
#include "shill/mockable.h"
#include "shill/refptr_types.h"
#include "shill/rpc_task.h"

namespace shill {

class CellularCapability;
class Error;
class ExternalTask;
class NetlinkSockDiag;
class ProcessManager;

class Cellular : public Device,
                 public RpcTaskDelegate,
                 public MobileOperatorInfo::Observer {
 public:
  enum Type {
    kType3gpp,  // ModemManager1
    kTypeCdma,
    kTypeInvalid,
  };

  enum class State {
    // Initial state. No Capability exists.
    kDisabled,
    // A Modem object and a corresponding Capability have been created but the
    // Modem has not started.
    kEnabled,
    // A Start request has been sent to the Modem.
    kModemStarting,
    // The Modem Start has completed.
    kModemStarted,
    // A Stop request has been sent to the Modem.
    kModemStopping,
    // The modem has registered with a network. A Cellular Service will be
    // created if necessary and associated with this Device.
    kRegistered,
    // The modem has connected to a network.
    kConnected,
    // The network interface is up.
    kLinked,
  };

  // This enum must be kept in sync with ModemManager's MMModemState enum.
  enum ModemState {
    kModemStateFailed = -1,
    kModemStateUnknown = 0,
    kModemStateInitializing = 1,
    kModemStateLocked = 2,
    kModemStateDisabled = 3,
    kModemStateDisabling = 4,
    kModemStateEnabling = 5,
    kModemStateEnabled = 6,
    kModemStateSearching = 7,
    kModemStateRegistered = 8,
    kModemStateDisconnecting = 9,
    kModemStateConnecting = 10,
    kModemStateConnected = 11,
  };

  // Enum for SIM types
  enum SimType {
    kSimTypeUnknown = 0,
    kSimTypePsim = 1,
    kSimTypeEsim = 2,
  };

  // Used in Cellular and CellularCapability3gpp to store and pass properties
  // associated with a SIM Profile.
  struct SimProperties {
    size_t slot;
    std::string iccid;
    std::string eid;
    std::string operator_id;
    std::string spn;
    std::string imsi;
    bool operator==(const SimProperties& other) const {
      return slot == other.slot && iccid == other.iccid && eid == other.eid &&
             operator_id == other.operator_id && spn == other.spn &&
             imsi == other.imsi;
    }
  };

  // Static helper for logging.
  static std::string GetStateString(State state);
  static std::string GetModemStateString(ModemState modem_state);

  // |path| is the ModemManager.Modem DBus object path (e.g.,
  // "/org/freedesktop/ModemManager1/Modem/0"). |service| is the modem
  // mananager service name (e.g., /org/freedesktop/ModemManager1).
  Cellular(Manager* manager,
           const std::string& link_name,
           const std::string& address,
           int interface_index,
           Type type,
           const std::string& service,
           const RpcIdentifier& path);
  Cellular(const Cellular&) = delete;
  Cellular& operator=(const Cellular&) = delete;

  ~Cellular() override;

  // Returns the legacy identifier used by GetStorageIdentifier for loading
  // entries from older profiles. TODO(b/181843251): Remove after M94.
  std::string GetLegacyEquipmentIdentifier() const;

  // Returns the Capability type if |capability_| has been created.
  std::string GetTechnologyFamily(Error* error);

  // Returns the device id as a string if it has been set.
  std::string GetDeviceId(Error* error);

  // Inherited from Device.
  std::string GetStorageIdentifier() const override;
  bool Load(const StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;
  void Start(Error* error,
             const EnabledStateChangedCallback& callback) override;
  void Stop(Error* error, const EnabledStateChangedCallback& callback) override;
  bool IsUnderlyingDeviceEnabled() const override;
  void LinkEvent(unsigned int flags, unsigned int change) override;
  void Scan(Error* error, const std::string& /*reason*/) override;
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
  void DropConnection() override;
  void SetServiceState(Service::ConnectState state) override;
  void SetServiceFailure(Service::ConnectFailure failure_state) override;
  void SetServiceFailureSilent(Service::ConnectFailure failure_state) override;
  void OnConnected() override;
  void OnBeforeSuspend(const ResultCallback& callback) override;
  void OnAfterResume() override;
  std::vector<GeolocationInfo> GetGeolocationObjects() const override;

  // Performs the necessary steps to bring the service to the activated state,
  // once an online payment has been done.
  void CompleteActivation(Error* error);

  // Asynchronously detach then re-attach the network.
  virtual void ReAttach();

  // Cancel any pending connect request.
  void CancelPendingConnect();

  void OnScanReply(const Stringmaps& found_networks, const Error& error);

  // Asynchronously queries capability for cellular location.
  void PollLocation();

  void HandleNewSignalQuality(uint32_t strength);

  // Processes a change in the modem registration state, possibly creating,
  // destroying or updating the CellularService.
  void HandleNewRegistrationState();

  // Called when the associated Modem object is destroyed.
  void OnModemDestroyed();

  // Returns true if |service| is connectable.
  bool GetConnectable(CellularService* service) const;

  // Asynchronously connects the modem to |service|. Changes the primary slot if
  // required. Populates |error| on failure, leaves it unchanged otherwise.
  virtual void Connect(CellularService* service, Error* error);

  // Asynchronously disconnects the modem from the current network and populates
  // |error| on failure, leaves it unchanged otherwise.
  virtual void Disconnect(Error* error, const char* reason);

  // Called when the Modem object is created to set the initial properties.
  void SetInitialProperties(const InterfaceToProperties& properties);

  void OnModemStateChanged(ModemState new_state);

  // Called to send detailed metrics for the last connection attempt.
  void NotifyDetailedCellularConnectionResult(const Error& error,
                                              const shill::Stringmap& apn_info);

  // Is the underlying device in the process of activating?
  bool IsActivating() const;

  // Starts and stops scheduled location polls
  void StartLocationPolling();
  void StopLocationPolling();

  // Initiate PPP link. Called from capabilities.
  virtual void StartPPP(const std::string& serial_device);
  // Callback for |ppp_task_|.
  virtual void OnPPPDied(pid_t pid, int exit);

  // Implements RpcTaskDelegate, for |ppp_task_|.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

  // Register DBus Properties exposed by the Device interface of shill.
  void RegisterProperties();

  // |dbus_path| and |mac_address| may change if the associated Modem restarts.
  void UpdateModemProperties(const RpcIdentifier& dbus_path,
                             const std::string& mac_address);

  // Returns a unique identifier for a SIM Card. For physical cards this will be
  // the ICCID and there should only be one matching service. For eSIM cards,
  // this will be the eUICCID (eID) and there may be multiple services
  // associated with the card.
  const std::string& GetSimCardId() const;

  // Returns true if |sim_card_id| matches any available SIM cards.
  bool HasSimCardId(const std::string& sim_card_id) const;

  // Sets the SIM properties and the primary SIM, and updates services and
  // state accordingly.
  void SetSimProperties(const std::vector<SimProperties>& slot_properties,
                        size_t primary_slot);

  // Called when an OTA profile update arrives from the network.
  void OnProfilesChanged();

  // Returns a list of APNs to try, in the following order:
  // - the APN, if any, that was set by the user
  // - APNs that the modem reports as provisioned profiles
  // - the list of APNs found in the mobile broadband provider DB for the
  //   home provider associated with the current SIM
  // - the last APN that resulted in a successful connection attempt on the
  //   current network (if any)
  std::deque<Stringmap> BuildApnTryList() const;

  // Update the home provider from the information in |operator_info|. This
  // information may be from the SIM / received OTA.
  void UpdateHomeProvider(const MobileOperatorInfo* operator_info);

  // Update the serving operator using information in |operator_info|.
  // Additionally, if |home_provider_info| is not nullptr, use it to come up
  // with a better name.
  void UpdateServingOperator(const MobileOperatorInfo* operator_info,
                             const MobileOperatorInfo* home_provider_info);

  // Implements MobileOperatorInfo::Observer:
  void OnOperatorChanged() override;

  const CellularServiceRefPtr& service() const { return service_; }
  MobileOperatorInfo* home_provider_info() const {
    return home_provider_info_.get();
  }
  MobileOperatorInfo* serving_operator_info() const {
    return serving_operator_info_.get();
  }
  State state() const { return state_; }
  ModemState modem_state() const { return modem_state_; }
  bool allow_roaming_property() const { return allow_roaming_; }

  bool StateIsConnected();
  bool StateIsRegistered();
  bool StateIsStarted();

  // DBus property getters
  const std::string& dbus_service() const { return dbus_service_; }
  const RpcIdentifier& dbus_path() const { return dbus_path_; }
  const Stringmap& home_provider() const { return home_provider_; }
  bool scanning_supported() const { return scanning_supported_; }
  const std::string& eid() const { return eid_; }
  const std::string& esn() const { return esn_; }
  const std::string& firmware_revision() const { return firmware_revision_; }
  const std::string& hardware_revision() const { return hardware_revision_; }
  const DeviceId* device_id() const { return device_id_.get(); }
  const std::string& imei() const { return imei_; }
  const std::string& imsi() const { return imsi_; }
  const std::string& mdn() const { return mdn_; }
  const std::string& meid() const { return meid_; }
  const std::string& min() const { return min_; }
  const std::string& manufacturer() const { return manufacturer_; }
  const std::string& model_id() const { return model_id_; }
  const std::string& mm_plugin() const { return mm_plugin_; }
  bool scanning() const { return scanning_; }

  const std::string& selected_network() const { return selected_network_; }
  const Stringmaps& found_networks() const { return found_networks_; }
  bool sim_present() const { return sim_present_; }
  const Stringmaps& apn_list() const { return apn_list_; }
  const std::string& iccid() const { return iccid_; }
  bool allow_roaming() const { return allow_roaming_; }
  bool policy_allow_roaming() const { return policy_allow_roaming_; }
  bool provider_requires_roaming() const { return provider_requires_roaming_; }
  bool use_attach_apn() const { return use_attach_apn_; }

  Type type() const { return type_; }
  bool inhibited() const { return inhibited_; }
  const std::string& connect_pending_iccid() const {
    return connect_pending_iccid_;
  }

  // Property setters. TODO(b/176904580): Rename SetFoo and alphabetize.
  void SetScanningSupported(bool scanning_supported);
  void SetEquipmentId(const std::string& equipment_id);
  void SetEsn(const std::string& esn);
  void SetFirmwareRevision(const std::string& firmware_revision);
  void SetHardwareRevision(const std::string& hardware_revision);
  void SetDeviceId(std::unique_ptr<DeviceId> device_id);
  void SetImei(const std::string& imei);
  void SetMdn(const std::string& mdn);
  void SetMeid(const std::string& meid);
  void SetMin(const std::string& min);
  void SetManufacturer(const std::string& manufacturer);
  void SetModelId(const std::string& model_id);
  void SetMMPlugin(const std::string& mm_plugin);

  void SetSelectedNetwork(const std::string& selected_network);
  void SetFoundNetworks(const Stringmaps& found_networks);
  void SetProviderRequiresRoaming(bool provider_requires_roaming);
  bool IsRoamingAllowed();
  void SetApnList(const Stringmaps& apn_list);

  // Sets a Service for testing. When set, Cellular does not create or destroy
  // the associated Service.
  void SetServiceForTesting(CellularServiceRefPtr service);

  void set_home_provider_for_testing(const Stringmap& home_provider) {
    home_provider_ = home_provider;
  }
  void set_home_provider_info_for_testing(
      MobileOperatorInfo* home_provider_info) {
    home_provider_info_.reset(home_provider_info);
  }
  void set_serving_operator_info_for_testing(
      MobileOperatorInfo* serving_operator_info) {
    serving_operator_info_.reset(serving_operator_info);
  }
  void clear_found_networks_for_testing() { found_networks_.clear(); }
  CellularCapability* capability_for_testing() { return capability_.get(); }
  const KeyValueStores& sim_slot_info_for_testing() { return sim_slot_info_; }
  void set_modem_state_for_testing(ModemState state) { modem_state_ = state; }
  void set_use_attach_apn_for_testing(bool on) { use_attach_apn_ = on; }
  void set_eid_for_testing(const std::string& eid) { eid_ = eid; }
  void set_iccid_for_testing(const std::string& iccid) { iccid_ = iccid; }
  void set_state_for_testing(const State& state) { state_ = state; }

  // Delay before connecting to pending connect requests. This helps prevent
  // connect failures while the Modem is still starting up.
  static constexpr base::TimeDelta kPendingConnectDelay = base::Seconds(2);

 private:
  friend class CellularTest;
  friend class CellularCapabilityCdmaTest;
  friend class CellularServiceTest;
  friend class CellularServiceProviderTest;
  friend class ModemTest;
  FRIEND_TEST(CellularTest, ChangeServiceState);
  FRIEND_TEST(CellularTest, ChangeServiceStatePPP);
  FRIEND_TEST(CellularTest, Connect);
  FRIEND_TEST(CellularTest, ConnectFailure);
  FRIEND_TEST(CellularTest, ConnectFailureNoService);
  FRIEND_TEST(CellularTest, ConnectSuccessNoService);
  FRIEND_TEST(CellularTest, CustomSetterNoopChange);
  FRIEND_TEST(CellularTest, Disconnect);
  FRIEND_TEST(CellularTest, DisconnectFailure);
  FRIEND_TEST(CellularTest, DropConnection);
  FRIEND_TEST(CellularTest, DropConnectionPPP);
  FRIEND_TEST(CellularTest, EstablishLinkDHCP);
  FRIEND_TEST(CellularTest, EstablishLinkPPP);
  FRIEND_TEST(CellularTest, EstablishLinkStatic);
  FRIEND_TEST(CellularTest, FriendlyServiceName);
  FRIEND_TEST(CellularTest, HomeProviderServingOperator);
  FRIEND_TEST(CellularTest, LinkEventUpWithPPP);
  FRIEND_TEST(CellularTest, LinkEventUpWithoutPPP);
  FRIEND_TEST(CellularTest, LinkEventWontDestroyService);
  FRIEND_TEST(CellularTest, ModemStateChangeDisable);
  FRIEND_TEST(CellularTest, ModemStateChangeEnable);
  FRIEND_TEST(CellularTest, ModemStateChangeStaleConnected);
  FRIEND_TEST(CellularTest, ModemStateChangeValidConnected);
  FRIEND_TEST(CellularTest, Notify);
  FRIEND_TEST(CellularTest, OnAfterResumeDisableInProgressWantDisabled);
  FRIEND_TEST(CellularTest, OnAfterResumeDisableQueuedWantEnabled);
  FRIEND_TEST(CellularTest, OnAfterResumeDisabledWantDisabled);
  FRIEND_TEST(CellularTest, OnAfterResumeDisabledWantEnabled);
  FRIEND_TEST(CellularTest, OnAfterResumePowerDownInProgressWantEnabled);
  FRIEND_TEST(CellularTest, OnPPPDied);
  FRIEND_TEST(CellularTest, CompareApns);
  FRIEND_TEST(CellularTest, PPPConnectionFailedAfterAuth);
  FRIEND_TEST(CellularTest, PPPConnectionFailedBeforeAuth);
  FRIEND_TEST(CellularTest, PPPConnectionFailedDuringAuth);
  FRIEND_TEST(CellularTest, PPPConnectionFailedAfterConnect);
  FRIEND_TEST(CellularTest, ScanAsynchronousFailure);
  FRIEND_TEST(CellularTest, ScanImmediateFailure);
  FRIEND_TEST(CellularTest, ScanSuccess);
  FRIEND_TEST(CellularTest, SetAllowRoaming);
  FRIEND_TEST(CellularTest, SetPolicyAllowRoaming);
  FRIEND_TEST(CellularTest, SetUseAttachApn);
  FRIEND_TEST(CellularTest, StopPPPOnDisconnect);
  FRIEND_TEST(CellularTest, StorageIdentifier);
  FRIEND_TEST(CellularTest, StartConnected);
  FRIEND_TEST(CellularTest, StartCdmaRegister);
  FRIEND_TEST(CellularTest, StartGsmRegister);
  FRIEND_TEST(CellularTest, StartLinked);
  FRIEND_TEST(CellularTest, StartPPP);
  FRIEND_TEST(CellularTest, StartPPPAfterEthernetUp);
  FRIEND_TEST(CellularTest, StartPPPAlreadyStarted);
  FRIEND_TEST(CellularTest, GetGeolocationObjects);

  // Names of properties in storage
  static const char kAllowRoaming[];
  static const char kPolicyAllowRoaming[];
  static const char kUseAttachApn[];

  // Modem Manufacturer Name
  static const char kQ6V5ModemManufacturerName[];

  // Modem driver remoteproc pattern
  static const char kQ6V5RemoteprocPattern[];

  // Modem driver sysfs base path
  static const char kQ6V5SysfsBasePath[];

  // Modem driver name
  static const char kQ6V5DriverName[];

  // Time between stop and start of modem device
  static constexpr base::TimeDelta kModemResetTimeout = base::Seconds(1);

  // Time between asynchronous calls to ModemManager1's GetLocation()
  static constexpr base::TimeDelta kPollLocationInterval = base::Minutes(5);

  enum class StopSteps {
    // Initial state.
    kStopModem,
    // The modem has been stopped.
    kModemStopped,
  };

  void CreateCapability();
  void DestroyCapability();

  // TODO(b/173635024): Fix order of cellular.h and .cc methods.
  void StartModem(Error* error, const EnabledStateChangedCallback& callback);
  void StartModemCallback(const EnabledStateChangedCallback& callback,
                          const Error& error);
  void StopModemCallback(const EnabledStateChangedCallback& callback,
                         const Error& error);
  void DestroySockets();

  bool ShouldBringNetworkInterfaceDownAfterDisabled() const override;

  void SetDbusPath(const shill::RpcIdentifier& dbus_path);
  void SetState(State state);
  void SetModemState(ModemState modem_state_state);
  void SetScanning(bool scanning);
  void SetScanningProperty(bool scanning);

  void OnEnabled();
  void OnConnecting();
  void OnDisconnected();
  void OnDisconnectFailed();
  void NotifyCellularConnectionResult(const Error& error,
                                      const std::string& iccid,
                                      bool is_user_triggered);
  // Invoked when the modem is connected to the cellular network to transition
  // to the network-connected state and bring the network interface up.
  void EstablishLink();

  void HandleLinkEvent(unsigned int flags, unsigned int change);

  void InitCapability(Type type);

  void SetPrimarySimProperties(const SimProperties& properties);
  void SetSimSlotProperties(const std::vector<SimProperties>& slot_properties,
                            int primary_slot);

  void SetRegistered();

  // Creates or destroys services as required.
  void UpdateServices();

  // Creates and registers services for the available SIMs and sets
  // |service_| to the primary (active) service.
  void CreateServices();

  // Destroys all services and the connection, if any. This also eliminates any
  // circular references between this device and the associated service,
  // allowing eventual device destruction.
  void DestroyAllServices();

  // Compares 2 APN configurations ignoring fields that are not connection
  // properties. This is needed since we add tags to the APN Stringmap to track
  // information related to each APN, but these properties are not used as
  // connection properties.
  bool CompareApns(const Stringmap& apn1, const Stringmap& apn2) const;

  // Creates or updates services for secondary SIMs.
  void UpdateSecondaryServices();

  // HelpRegisterDerived*: Expose a property over RPC, with the name |name|.
  //
  // Reads of the property will be handled by invoking |get|.
  // Writes to the property will be handled by invoking |set|.
  // Clearing the property will be handled by PropertyStore.
  void HelpRegisterDerivedBool(const std::string& name,
                               bool (Cellular::*get)(Error* error),
                               bool (Cellular::*set)(const bool& value,
                                                     Error* error));
  void HelpRegisterConstDerivedString(
      const std::string& name, std::string (Cellular::*get)(Error* error));

  void OnConnectReply(std::string iccid,
                      bool is_user_triggered,
                      const Error& error);
  void OnDisconnectReply(const Error& error);

  void ReAttachOnDetachComplete(const Error& error);

  // DBus accessors
  bool GetPolicyAllowRoaming(Error* /*error*/);
  bool SetPolicyAllowRoaming(const bool& value, Error* error);
  bool GetInhibited(Error* /*error*/);
  bool SetInhibited(const bool& inhibited, Error* error);
  KeyValueStore GetSimLockStatus(Error* error);
  void SetSimPresent(bool sim_present);

  // DBUS accessors to read/modify the use of an Attach APN
  bool GetUseAttachApn(Error* /*error*/) { return use_attach_apn_; }
  bool SetUseAttachApn(const bool& value, Error* error);

  // When shill terminates or ChromeOS suspends, this function is called to
  // disconnect from the cellular network.
  void StartTermination();

  // This method is invoked upon the completion of StartTermination().
  void OnTerminationCompleted(const Error& error);

  // This function does the final cleanup once a disconnect request terminates.
  // Returns true, if the device state is successfully changed.
  bool DisconnectCleanup();

  // Executed after the asynchronous CellularCapability::StartModem
  // call from OnAfterResume completes.
  static void LogRestartModemResult(const Error& error);

  // Handler to reset qcom-q6v5-mss based modems
  bool ResetQ6V5Modem();

  // Get reset path for Q6V5 modem
  base::FilePath GetQ6V5ModemResetPath();

  // Handler to check if modem is based on qcom-q6v5-mss
  bool IsQ6V5Modem();

  // Execute the next step to Stop cellular.
  void StopStep(Error* error,
                const EnabledStateChangedCallback& callback,
                const Error& error_result);

  // Terminate the pppd process associated with this Device, and remove the
  // association between the PPPDevice and our CellularService. If this
  // Device is not using PPP, the method has no effect.
  void StopPPP();

  // Handlers for PPP events. Dispatched from Notify().
  void OnPPPAuthenticated();
  void OnPPPAuthenticating();
  void OnPPPConnected(const std::map<std::string, std::string>& params);

  bool ModemIsEnabledButNotRegistered();

  void SetPendingConnect(const std::string& iccid);
  void ConnectToPending();
  void ConnectToPendingAfterDelay();
  void ConnectToPendingFailed(Service::ConnectFailure failure);
  void ConnectToPendingCancel();

  void UpdateScanning();
  void GetLocationCallback(const std::string& gpp_lac_ci_string,
                           const Error& error);
  void PollLocationTask();

  State state_ = State::kDisabled;
  ModemState modem_state_ = kModemStateUnknown;

  struct LocationInfo {
    std::string mcc;
    std::string mnc;
    std::string lac;
    std::string ci;
  };
  LocationInfo location_info_;

  // Operator info objects. These objects receive updates as we receive
  // information about the network operators from the SIM or OTA. In turn, they
  // send out updates through their observer interfaces whenever the identity of
  // the network operator changes, or any other property of the operator
  // changes.
  std::unique_ptr<MobileOperatorInfo> home_provider_info_;
  std::unique_ptr<MobileOperatorInfo> serving_operator_info_;

  // ///////////////////////////////////////////////////////////////////////////
  // All DBus Properties exposed by the Cellular device.
  // Properties common to GSM and CDMA modems.
  const std::string dbus_service_;  // org.*.ModemManager*
  RpcIdentifier dbus_path_;         // ModemManager.Modem
  // Used because we currently expose |dbus_path| as a string property.
  std::string dbus_path_str_;

  Stringmap home_provider_;

  bool scanning_supported_ = false;
  std::string equipment_id_;
  std::string esn_;
  std::string firmware_revision_;
  std::string hardware_revision_;
  std::unique_ptr<DeviceId> device_id_;
  std::string imei_;
  std::string manufacturer_;
  std::string mdn_;
  std::string meid_;
  std::string min_;
  std::string model_id_;
  std::string mm_plugin_;
  bool scanning_ = false;
  bool polling_location_ = false;
  base::CancelableClosure poll_location_task_;

  // GSM only properties.
  // They are always exposed but are non empty only for GSM technology modems.
  std::string selected_network_;
  Stringmaps found_networks_;
  uint16_t scan_interval_ = 0;
  Stringmaps apn_list_;

  // Primary SIM properties.
  std::string eid_;  // SIM eID, aka eUICCID
  std::string iccid_;
  std::string imsi_;
  bool sim_present_ = false;

  // vector of SimProperties, ordered by slot.
  std::vector<SimProperties> sim_slot_properties_;
  int primary_sim_slot_ = -1;
  // vector of KeyValueStore dictionaries, emitted as Device.SIMSlotInfo.
  KeyValueStores sim_slot_info_;

  // End of DBus properties.
  // ///////////////////////////////////////////////////////////////////////////

  Type type_;
  std::unique_ptr<CellularCapability> capability_;
  std::optional<InterfaceToProperties> initial_properties_;

  ProcessManager* process_manager_;

  // The active CellularService instance for this Device. This will always be
  // set to a valid service instance.
  CellularServiceRefPtr service_;
  // When set in tests, |service_| is not created or destroyed by Cellular.
  CellularServiceRefPtr service_for_testing_;

  // User preference to allow or disallow roaming before M92. Used as a default
  // until Chrome ties its roaming toggle to Service.AllowRoaming (b/184375691)
  bool allow_roaming_ = false;

  // If an operator has no home network, then set this flag. This overrides
  // all other roaming preferences, and allows roaming unconditionally.
  bool policy_allow_roaming_ = true;

  bool provider_requires_roaming_ = false;

  // Chrome flags to enable setting the attach APN from the host
  bool use_attach_apn_ = false;

  // Reflects the Device property indicating that the modem is inhibted. The
  // property is not persisted and is reset to false when the modem starts.
  bool inhibited_ = false;

  // Track whether a user initiated scan is in prgoress (initiated via ::Scan)
  bool proposed_scan_in_progress_ = false;

  // Flag indicating that a disconnect has been explicitly requested.
  bool explicit_disconnect_ = false;

  std::unique_ptr<ExternalTask> ppp_task_;
  PPPDeviceRefPtr ppp_device_;
  bool is_ppp_authenticating_ = false;

  std::unique_ptr<NetlinkSockDiag> socket_destroyer_;

  // Used to keep scanning=true while the Modem is restarting.
  // TODO(b/177588333): Make Modem and/or the MM dbus API more robust.
  base::CancelableClosure scanning_clear_callback_;

  // If a Connect request occurs while the Modem is busy, do not connect
  // immediately, instead set |connect_pending_iccid_|. The connect will occur
  // after a delay once Scanning is set to false.
  std::string connect_pending_iccid_;
  base::CancelableClosure connect_pending_callback_;
  // Used to cancel a pending connect while waiting for Modem registration.
  base::CancelableClosure connect_cancel_callback_;

  // Legacy device storage identifier, used for removing legacy entry.
  std::string legacy_storage_id_;

  // A Map containing the last connection results. ICCID is used as the key.
  std::unordered_map<std::string, Error::Type>
      last_cellular_connection_results_;

  // The current step of the Stop process.
  std::optional<StopSteps> stop_step_;

  base::WeakPtrFactory<Cellular> weak_ptr_factory_{this};
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_H_
