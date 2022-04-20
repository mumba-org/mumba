// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DEVICE_H_
#define SHILL_DEVICE_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "shill/adaptor_interfaces.h"
#include "shill/callbacks.h"
#include "shill/connection.h"
#include "shill/connection_diagnostics.h"
#include "shill/event_dispatcher.h"
#include "shill/geolocation_info.h"
#include "shill/ipconfig.h"
#include "shill/net/ip_address.h"
#include "shill/network/dhcp_controller.h"
#include "shill/portal_detector.h"
#include "shill/refptr_types.h"
#include "shill/service.h"
#include "shill/store/property_store.h"
#include "shill/technology.h"

namespace shill {

class ControlInterface;
class DHCPProvider;
class DeviceAdaptorInterface;
class Error;
class EventDispatcher;
class Manager;
class Metrics;
class RoutingTable;
class RTNLHandler;

// Device superclass.  Individual network interfaces types will inherit from
// this class.
class Device : public base::RefCounted<Device> {
 public:
  // A constructor for the Device object
  Device(Manager* manager,
         const std::string& link_name,
         const std::string& mac_address,
         int interface_index,
         Technology technology);
  Device(const Device&) = delete;
  Device& operator=(const Device&) = delete;

  // Initialize type-specific network interface properties.
  virtual void Initialize();

  // Enable or disable the device. This is a convenience method for
  // cases where we want to SetEnabledNonPersistent, but don't care
  // about the results.
  mockable void SetEnabled(bool enable);
  // Enable or disable the device. Unlike SetEnabledPersistent, it does not
  // save the setting in the profile.
  //
  // TODO(quiche): Replace both of the next two methods with calls to
  // SetEnabledChecked.
  mockable void SetEnabledNonPersistent(bool enable,
                                        Error* error,
                                        const ResultCallback& callback);
  // Enable or disable the device, and save the setting in the profile.
  // The setting is persisted before the enable or disable operation
  // starts, so that even if it fails, the user's intent is still recorded
  // for the next time shill restarts.
  mockable void SetEnabledPersistent(bool enable,
                                     Error* error,
                                     const ResultCallback& callback);
  // Enable or disable the Device, depending on |enable|.
  // Save the new setting to the profile, if |persist| is true.
  // Report synchronous errors using |error|, and asynchronous completion
  // with |callback|.
  void SetEnabledChecked(bool enable,
                         bool persist,
                         Error* error,
                         const ResultCallback& callback);
  // Similar to SetEnabledChecked, but without coherence checking, and
  // without saving the new value of |enable| to the profile. If you
  // are rational (i.e. not Cellular), you should use
  // SetEnabledChecked instead.
  void SetEnabledUnchecked(bool enable,
                           Error* error,
                           const ResultCallback& callback);

  // Returns true if the underlying device reports that it is already enabled.
  // Used when the device is registered with the Manager, so that shill can
  // sync its state/ with the true state of the device. The default is to
  // report false.
  virtual bool IsUnderlyingDeviceEnabled() const;

  virtual void LinkEvent(unsigned flags, unsigned change);

  // The default implementation sets |error| to kNotSupported.
  virtual void Scan(Error* error, const std::string& reason);
  virtual void RegisterOnNetwork(const std::string& network_id,
                                 Error* error,
                                 const ResultCallback& callback);
  virtual void RequirePin(const std::string& pin,
                          bool require,
                          Error* error,
                          const ResultCallback& callback);
  virtual void EnterPin(const std::string& pin,
                        Error* error,
                        const ResultCallback& callback);
  virtual void UnblockPin(const std::string& unblock_code,
                          const std::string& pin,
                          Error* error,
                          const ResultCallback& callback);
  virtual void ChangePin(const std::string& old_pin,
                         const std::string& new_pin,
                         Error* error,
                         const ResultCallback& callback);
  virtual void Reset(Error* error, const ResultCallback& callback);

  void StopIPv6();
  void StartIPv6();
  mockable void EnableIPv6Privacy();

  // Returns true if the selected service on the device (if any) is connected.
  // Returns false if there is no selected service, or if the selected service
  // is not connected.
  bool IsConnected() const;

  // Called by Device so that subclasses can run hooks on the selected service
  // getting an IP.  Subclasses should call up to the parent first.
  virtual void OnConnected();

  // Returns true if the selected service on the device (if any) is connected
  // and matches the passed-in argument |service|.  Returns false if there is
  // no connected service, or if it does not match |service|.
  mockable bool IsConnectedToService(const ServiceRefPtr& service) const;

  // Returns true if the DHCP parameters provided indicate that we are tethered
  // to a mobile device.
  mockable bool IsConnectedViaTether() const;

  // Called by Device so that subclasses can run hooks on the selected service
  // changed. This function is called after the |selected_service_| changed so
  // the subclasses can call the getter to retrieve the new selected service.
  // Note that the base class does nothing here so the subclasses don't need to
  // call up to the parent.
  virtual void OnSelectedServiceChanged(const ServiceRefPtr& old_service);

  // Restart the portal detection process on a connected device.  This is
  // useful if the properties on the connected service have changed in a
  // way that may affect the decision to run portal detection at all.
  // Returns true if portal detection was started.
  mockable bool RestartPortalDetection();

  // Called by the manager to start a single connectivity test.  This is used to
  // log connection state triggered by a user feedback log request.
  mockable bool StartConnectivityTest();

  // Requests that portal detection be done, if this device has the default
  // connection.  Returns true if portal detection was started.
  mockable bool RequestPortalDetection();

  const RpcIdentifier& GetRpcIdentifier() const;
  virtual std::string GetStorageIdentifier() const;

  // Returns a list of Geolocation objects. Each object is multiple
  // key-value pairs representing one entity that can be used for
  // Geolocation.
  virtual std::vector<GeolocationInfo> GetGeolocationObjects() const;

  // Enable or disable same-net multi-home support for this interface.  When
  // enabled, ARP filtering is enabled in order to avoid the "ARP Flux"
  // effect where peers may end up with inaccurate IP address mappings due to
  // the default Linux ARP transmit / reply behavior.  See
  // http://linux-ip.net/html/ether-arp.html for more details on this effect.
  mockable void SetIsMultiHomed(bool is_multi_homed);

  // Used for devices that are managed by an entity other than shill.
  // If true, shill will not attempt to change the device's IP
  // address, subnet mask, broadcast address, or manipulate the interface
  // state.  This setting is disabled by default.
  void SetFixedIpParams(bool fixed_ip_params);

  const std::string& mac_address() const { return mac_address_; }
  const std::string& link_name() const { return link_name_; }
  int interface_index() const { return interface_index_; }
  mockable Connection* connection() const { return connection_.get(); }
  bool enabled() const { return enabled_; }
  bool enabled_persistent() const { return enabled_persistent_; }
  mockable Technology technology() const { return technology_; }
  std::string GetTechnologyString(Error* error);

  const IPConfigRefPtr& ipconfig() const { return ipconfig_; }
  const IPConfigRefPtr& ip6config() const { return ip6config_; }
  void set_ipconfig(const IPConfigRefPtr& config) { ipconfig_ = config; }
  void set_ip6config(const IPConfigRefPtr& config) { ip6config_ = config; }

  // Returns a string that is guaranteed to uniquely identify this Device
  // instance.
  const std::string& UniqueName() const;

  // Returns a WeakPtr of the Device.
  base::WeakPtr<Device> AsWeakPtr() { return weak_ptr_factory_.GetWeakPtr(); }

  PropertyStore* mutable_store() { return &store_; }
  const PropertyStore& store() const { return store_; }
  RTNLHandler* rtnl_handler() { return rtnl_handler_; }

  EventDispatcher* dispatcher() const;

  // Load configuration for the device from |storage|.  This may include
  // instantiating non-visible services for which configuration has been
  // stored.
  virtual bool Load(const StoreInterface* storage);

  // Save configuration for the device to |storage|.
  virtual bool Save(StoreInterface* storage);

  void set_dhcp_provider(DHCPProvider* provider) { dhcp_provider_ = provider; }

  DeviceAdaptorInterface* adaptor() const { return adaptor_.get(); }

  // Suspend event handler. Called by Manager before the system
  // suspends. This handler, along with any other suspend handlers,
  // will have Manager::kTerminationActionsTimeoutMilliseconds to
  // execute before the system enters the suspend state. |callback|
  // must be invoked after all synchronous and/or asynchronous actions
  // this function performs complete. Code that needs to run on exit should use
  // Manager::AddTerminationAction, rather than OnBeforeSuspend.
  //
  // The default implementation invokes the |callback| immediately, since
  // there is nothing to be done in the general case.
  virtual void OnBeforeSuspend(const ResultCallback& callback);

  // Resume event handler. Called by Manager as the system resumes.
  // The base class implementation takes care of renewing a DHCP lease
  // (if necessary). Derived classes may implement any technology
  // specific requirements by overriding, but should include a call to
  // the base class implementation.
  virtual void OnAfterResume();

  // This method is invoked when the system resumes from suspend temporarily in
  // the "dark resume" state. The system will reenter suspend in
  // Manager::kTerminationActionsTimeoutMilliseconds. |callback| must be invoked
  // after all synchronous and/or asynchronous actions this function performs
  // and/or posts complete.
  //
  // The default implementation invokes the |callback| immediately, since
  // there is nothing to be done in the general case.
  virtual void OnDarkResume(const ResultCallback& callback);

  // Destroy the lease, if any, with this |name|.
  // Called by the service during Unload() as part of the cleanup sequence.
  mockable void DestroyIPConfigLease(const std::string& name);

  // Called by DeviceInfo when the kernel adds or removes a globally-scoped
  // IPv6 address from this interface.
  mockable void OnIPv6AddressChanged(const IPAddress* address);

  // Called by DeviceInfo when the kernel receives a update for IPv6 DNS server
  // addresses from this interface.
  mockable void OnIPv6DnsServerAddressesChanged();

  // Sets MAC address source for USB Ethernet device. Callback will only be
  // invoke when device successfully changed MAC address or failed to change MAC
  // address.
  virtual void SetUsbEthernetMacAddressSource(const std::string& source,
                                              Error* error,
                                              const ResultCallback& callback);

  // Initiate renewal of existing DHCP lease.
  void RenewDHCPLease(bool from_dbus, Error* error);

  // Creates a byte vector from a colon-separated hardware address string.
  static std::vector<uint8_t> MakeHardwareAddressFromString(
      const std::string& address_string);

  // Creates a colon-separated hardware address string from a byte vector.
  static std::string MakeStringFromHardwareAddress(
      const std::vector<uint8_t>& address_data);

  // Request the WiFi device to roam to AP with |addr|.
  // This call will send Roam command to wpa_supplicant.
  virtual bool RequestRoam(const std::string& addr, Error* error);

  const ServiceRefPtr& selected_service() const { return selected_service_; }

  // Drops the current connection and the selected service, if any.  Does not
  // change the state of the previously selected service.
  mockable void ResetConnection();

  // If the status of browser traffic blackholing changed, this will restart
  // the active connection with the right setting.
  mockable void UpdateBlackholeUserTraffic();

  // Responds to a neighbor reachability event from patchpanel. The base class
  // does nothing here so the derived class doesn't need to call this.
  virtual void OnNeighborReachabilityEvent(
      const IPAddress& ip_address,
      patchpanel::NeighborReachabilityEventSignal::Role role,
      patchpanel::NeighborReachabilityEventSignal::EventType event_type);

  // Calculates the duration till a DHCP lease is due for renewal, and stores
  // this value in |result|. Returns std::nullopt if there is no upcoming DHCP
  // lease renewal, base::TimeDelta wrapped in std::optional otherwise.
  // TODO(jiejiang): Move this out of Device class before Device has multiple
  // active connection.
  std::optional<base::TimeDelta> TimeToNextDHCPLeaseRenewal();

  void set_selected_service_for_testing(ServiceRefPtr service) {
    selected_service_ = service;
  }

  void set_dhcp_controller_for_testing(
      std::unique_ptr<DHCPController> dhcp_controller) {
    dhcp_controller_ = std::move(dhcp_controller);
  }

 protected:
  friend class base::RefCounted<Device>;
  FRIEND_TEST(CellularServiceTest, IsAutoConnectable);
  FRIEND_TEST(CellularTest, ModemStateChangeDisable);
  FRIEND_TEST(CellularTest, UseNoArpGateway);
  FRIEND_TEST(DevicePortalDetectionTest, PortalIntervalIsZero);
  FRIEND_TEST(DevicePortalDetectionTest, RequestStartConnectivityTest);
  FRIEND_TEST(DevicePortalDetectionTest, RestartPortalDetection);
  FRIEND_TEST(DeviceTest, AcquireIPConfigWithoutSelectedService);
  FRIEND_TEST(DeviceTest, AcquireIPConfigWithDHCPProperties);
  FRIEND_TEST(DeviceTest, AvailableIPConfigs);
  FRIEND_TEST(DeviceTest, DestroyIPConfig);
  FRIEND_TEST(DeviceTest, DestroyIPConfigNULL);
  FRIEND_TEST(DeviceTest, ConfigWithMinimumMTU);
  FRIEND_TEST(DeviceTest, FetchTrafficCounters);
  FRIEND_TEST(DeviceTest, GetProperties);
  FRIEND_TEST(DeviceTest, IPConfigUpdatedFailureWithIPv6Config);
  FRIEND_TEST(DeviceTest, IPConfigUpdatedFailureWithIPv6Connection);
  FRIEND_TEST(DeviceTest, IsConnectedViaTether);
  FRIEND_TEST(DeviceTest, LinkMonitorFailure);
  FRIEND_TEST(DeviceTest, Load);
  FRIEND_TEST(DeviceTest, OnIPv6AddressChanged);
  FRIEND_TEST(DeviceTest, OnIPv6ConfigurationCompleted);
  FRIEND_TEST(DeviceTest, OnIPv6DnsServerAddressesChanged);
  FRIEND_TEST(DeviceTest, ResetConnection);
  FRIEND_TEST(DeviceTest, Save);
  FRIEND_TEST(DeviceTest, SelectedService);
  FRIEND_TEST(DeviceTest, SetEnabledNonPersistent);
  FRIEND_TEST(DeviceTest, SetEnabledPersistent);
  FRIEND_TEST(DeviceTest, ShouldUseArpGateway);
  FRIEND_TEST(DeviceTest, Start);
  FRIEND_TEST(DeviceTest, StartIPv6);
  FRIEND_TEST(DeviceTest, StartIPv6Disabled);
  FRIEND_TEST(DeviceTest, StartProhibited);
  FRIEND_TEST(DeviceTest, Stop);
  FRIEND_TEST(DeviceTest, StopWithFixedIpParams);
  FRIEND_TEST(DeviceTest, StopWithNetworkInterfaceDisabledAfterward);
  FRIEND_TEST(ManagerTest, ConnectedTechnologies);
  FRIEND_TEST(ManagerTest, DefaultTechnology);
  FRIEND_TEST(ManagerTest, DeviceRegistrationAndStart);
  FRIEND_TEST(ManagerTest, GetEnabledDeviceWithTechnology);
  FRIEND_TEST(ManagerTest, RefreshAllTrafficCountersTask);
  FRIEND_TEST(ManagerTest, SetEnabledStateForTechnology);
  FRIEND_TEST(WiFiMainTest, UseArpGateway);

  virtual ~Device();

  // Each device must implement this method to do the work needed to
  // enable the device to operate for establishing network connections.
  // The |error| argument, if not nullptr,
  // will refer to an Error that starts out with the value
  // Error::kOperationInitiated. This reflects the assumption that
  // enable (and disable) operations will usually be non-blocking,
  // and their completion will be indicated by means of an asynchronous
  // reply sometime later. There are two circumstances in which a
  // device's Start() method may overwrite |error|:
  //
  // 1. If an early failure is detected, such that the non-blocking
  //    part of the operation never takes place, then |error| should
  //    be set to the appropriate value corresponding to the type
  //    of failure. This is the "immediate failure" case.
  // 2. If the device is enabled without performing any non-blocking
  //    steps, then |error| should be Reset, i.e., its value set
  //    to Error::kSuccess. This is the "immediate success" case.
  //
  // In these two cases, because completion is immediate, |callback|
  // is not used. If neither of these two conditions holds, then |error|
  // should not be modified, and |callback| should be passed to the
  // method that will initiate the non-blocking operation.
  virtual void Start(Error* error,
                     const EnabledStateChangedCallback& callback) = 0;

  // Each device must implement this method to do the work needed to
  // disable the device, i.e., clear any running state, and make the
  // device no longer capable of establishing network connections.
  // The discussion for Start() regarding the use of |error| and
  // |callback| apply to Stop() as well.
  virtual void Stop(Error* error,
                    const EnabledStateChangedCallback& callback) = 0;

  // Returns true if the associated network interface should be brought down
  // after the device is disabled, or false if that should be done before the
  // device is disabled.
  virtual bool ShouldBringNetworkInterfaceDownAfterDisabled() const;

  // The EnabledStateChangedCallback that gets passed to the device's
  // Start() and Stop() methods is bound to this method. |callback|
  // is the callback that was passed to SetEnabled().
  void OnEnabledStateChanged(const ResultCallback& callback,
                             const Error& error);

  // Update the device state to the pending state.
  void UpdateEnabledState();

  // Drops the currently selected service along with its IP configuration and
  // connection, if any.
  virtual void DropConnection();

  // If there's an IP configuration in |ipconfig_|, releases the IP address and
  // destroys the configuration instance.
  void DestroyIPConfig();

  // Creates a new DHCP IP configuration instance, stores it in |ipconfig_| and
  // requests a new IP configuration.  Saves the DHCP lease to the generic
  // lease filename based on the interface name.  Registers a callback to
  // IPConfigUpdatedCallback on IP configuration changes. Returns true if the IP
  // request was successfully sent.
  bool AcquireIPConfig();

  // Creates a new DHCP IP configuration instance, stores it in |ipconfig_| and
  // requests a new IP configuration.  Saves the DHCP lease to a filename
  // based on the passed-in |lease_name|.  Registers a callback to
  // IPConfigUpdatedCallback on IP configuration changes. Returns true if the IP
  // request was successfully sent.
  bool AcquireIPConfigWithLeaseName(const std::string& lease_name);

  // Assigns the IPv4 configuration |properties| to |ipconfig_|.
  void AssignIPConfig(const IPConfig::Properties& properties);

  // Assigns the IPv6 configuration |properties| to |ip6config_|.
  void AssignIPv6Config(const IPConfig::Properties& properties);

  // Callback registered with DHCPController. Also see the comment for
  // DHCPController::UpdateCallback.
  void OnIPConfigUpdatedFromDHCP(DHCPController* dhcp_controller,
                                 const IPConfig::Properties& properties,
                                 bool new_lease_acquired);

  // Called on when we get a new DHCP lease for this device. Derived class
  // should implement this function to listen to this event. Base class does
  // nothing.
  virtual void OnGetDHCPLease();

  // Called on when an IPv6 address is obtained from SLAAC. Derived class
  // should implement this function to listen to this event. Base class does
  // nothing.
  virtual void OnGetSLAACAddress();

  // Callback invoked on successful IP configuration updates.
  void OnIPConfigUpdated(const IPConfigRefPtr& ipconfig);

  // Called when IPv6 configuration changes.
  virtual void OnIPv6ConfigUpdated();

  // Called by Device so that subclasses can run hooks on the selected service
  // failing to get an IP.  The default implementation disconnects the selected
  // service with Service::kFailureDHCP.
  virtual void OnIPConfigFailure();

  // Selects a service to be "current" -- i.e. link-state or configuration
  // events that happen to the device are attributed to this service.
  void SelectService(const ServiceRefPtr& service);

  // Set the state of the |selected_service_|.
  virtual void SetServiceState(Service::ConnectState state);

  // Set the failure of the selected service (implicitly sets the state to
  // "failure").
  virtual void SetServiceFailure(Service::ConnectFailure failure_state);

  // Records the failure mode and time of the selected service, and
  // sets the Service state of the selected service to "Idle".
  // Avoids showing a failure mole in the UI.
  virtual void SetServiceFailureSilent(Service::ConnectFailure failure_state);

  // Indicates if the selected service is configured with a static IP address.
  bool IsUsingStaticIP() const;

  void HelpRegisterConstDerivedString(const std::string& name,
                                      std::string (Device::*get)(Error*));

  void HelpRegisterConstDerivedRpcIdentifier(
      const std::string& name, RpcIdentifier (Device::*get)(Error*));

  void HelpRegisterConstDerivedRpcIdentifiers(
      const std::string& name, RpcIdentifiers (Device::*get)(Error*));

  void HelpRegisterConstDerivedUint64(const std::string& name,
                                      uint64_t (Device::*get)(Error*));

  // Property getters reserved for subclasses
  ControlInterface* control_interface() const;
  bool enabled_pending() const { return enabled_pending_; }
  Metrics* metrics() const;
  Manager* manager() const { return manager_; }
  DHCPController* dhcp_controller() const { return dhcp_controller_.get(); }
  bool fixed_ip_params() const { return fixed_ip_params_; }

  virtual void set_mac_address(const std::string& mac_address);

  // Emit a given MAC Address via dbus. If empty or bad string is provided,
  // emit the hardware MAC address of the device.
  void EmitMACAddress(const std::string& mac_address = std::string());

 private:
  friend class CellularTest;
  friend class DeviceAdaptorInterface;
  friend class DeviceByteCountTest;
  friend class DevicePortalDetectionTest;
  friend class DeviceTest;
  friend class EthernetTest;
  friend class OpenVPNDriverTest;
  friend class TestDevice;
  friend class VirtualDeviceTest;
  friend class WiFiObjectTest;

  static const char kIPFlagDisableIPv6[];
  static const char kIPFlagAcceptRouterAdvertisements[];
  static const char kIPFlagAcceptDuplicateAddressDetection[];
  static const char kStoragePowered[];

  // Brings the associated network interface down unless |fixed_ip_params_| is
  // true, which indicates that the interface state shouldn't be changed.
  void BringNetworkInterfaceDown();

  // Configure static IP address parameters if the service provides them.
  void ConfigureStaticIPTask();

  // Set an IP configuration flag on the device. |family| should be "ipv6" or
  // "ipv4". |flag| should be the name of the flag to be set and |value| is
  // what this flag should be set to. Overridden by unit tests to pretend
  // writing to procfs.
  mockable bool SetIPFlag(IPAddress::Family family,
                          const std::string& flag,
                          const std::string& value);

  // Disable ARP filtering on the device.  The interface will exhibit the
  // default Linux behavior -- incoming ARP requests are responded to by all
  // interfaces.  Outgoing ARP requests can contain any local address.
  void DisableArpFiltering();

  // Enable ARP filtering on the device.  Incoming ARP requests are responded
  // to only by the interface(s) owning the address.  Outgoing ARP requests
  // will contain the best local address for the target.
  void EnableArpFiltering();

  RpcIdentifier GetSelectedServiceRpcIdentifier(Error* error);
  RpcIdentifiers AvailableIPConfigs(Error* error);

  // Emit a property change signal for the "IPConfigs" property of this device.
  void UpdateIPConfigsProperty();

  // Timer function for monitoring IPv6 DNS server's lifetime.
  void StartIPv6DNSServerTimer(base::TimeDelta lifetime);
  void StopIPv6DNSServerTimer();

  // Called when the lifetime for IPv6 DNS server expires.
  void IPv6DNSServerExpired();

  // Callback invoked on DHCP failures.
  void OnDHCPFailure(DHCPController* dhcp_controller);

  // Callback invoked when the static IP properties configured on the selected
  // service changed.
  void OnStaticIPConfigChanged();

  // Return true if given IP configuration contain both IP address and DNS
  // servers. Hence, ready to be used for network connection.
  bool IPConfigCompleted(const IPConfigRefPtr& ipconfig);

  // Setup network connection with given IP configuration, and start portal
  // detection on that connection.
  void SetupConnection(const IPConfigRefPtr& ipconfig);

  // Maintain connection state (Routes, IP Addresses and DNS) in the OS.
  void CreateConnection();

  // Remove connection state
  void DestroyConnection();

  // Set the system hostname to |hostname| if this device is configured to
  // do so.  If |hostname| is too long, truncate this parameter to fit within
  // the maximum hostname size.
  bool SetHostname(const std::string& hostname);

  // Called by the Portal Detector whenever a trial completes.  Device
  // subclasses that choose unique mappings from portal results to connected
  // states can override this method in order to do so.
  void PortalDetectorCallback(const PortalDetector::Result& result);

  // Initiate portal detection, if enabled for this device type.
  bool StartPortalDetection();

  // Stop portal detection if it is running.
  void StopPortalDetection();

  // Initiate connection diagnostics with the |result| from a completed portal
  // detection attempt.
  mockable bool StartConnectionDiagnosticsAfterPortalDetection(
      const PortalDetector::Result& result);

  // Stop connection diagnostics if it is running.
  void StopConnectionDiagnostics();

  // Stop connectivity tester if it exists.
  void StopConnectivityTest();

  // Called by |connection_diagnostics| after diagnostics have finished.
  void ConnectionDiagnosticsCallback(
      const std::string& connection_issue,
      const std::vector<ConnectionDiagnostics::Event>& diagnostic_events);

  // Called by the ConnectionTester whenever a connectivity test completes.
  void ConnectionTesterCallback(const PortalDetector::Result& result);

  // Stop all monitoring/testing activities on this device. Called when tearing
  // down or changing network connection on the device.
  void StopAllActivities();

  // Set the state of the selected service, with checks to make sure
  // the service is already in a connected state before doing so.
  void SetServiceConnectedState(Service::ConnectState state);

  // Specifies whether an ARP gateway should be used for the
  // device technology.
  virtual bool ShouldUseArpGateway() const;

  // Indicates if the selected service is configured with static nameservers.
  bool IsUsingStaticNameServers() const;

  // Atomically update the counters of the old service and the snapshot of the
  // new service. |GetTrafficCountersPatchpanelCallback| calls
  // |GetTrafficCountersCallback| using the |get_traffic_counters_callback_|
  // callback below. This is necessary because the callback that holds a
  // reference to the ServiceRefPtrs needs to be reset to release the
  // references. We can't directly cancel the callback we give to patchpanel
  // client since it expects a OnceCallback.
  void GetTrafficCountersCallback(
      const ServiceRefPtr& old_service,
      const ServiceRefPtr& new_service,
      const std::vector<patchpanel::TrafficCounter>& counters);
  void GetTrafficCountersPatchpanelCallback(
      unsigned int id, const std::vector<patchpanel::TrafficCounter>& counters);

  // Asynchronously get all the traffic counters for this device during a
  // selected_service_ change and update the counters and snapshots for the old
  // and new selected_service_ respectively.
  void FetchTrafficCounters(const ServiceRefPtr& old_service,
                            const ServiceRefPtr& new_service);

  // |enabled_persistent_| is the value of the Powered property, as
  // read from the profile. If it is not found in the profile, it
  // defaults to true. |enabled_| reflects the real-time state of
  // the device, i.e., enabled or disabled. |enabled_pending_| reflects
  // the target state of the device while an enable or disable operation
  // is occurring.
  //
  // Some typical sequences for these state variables are shown below.
  //
  // Shill starts up, profile has been read:
  //  |enabled_persistent_|=true   |enabled_|=false   |enabled_pending_|=false
  //
  // Shill acts on the value of |enabled_persistent_|, calls SetEnabled(true):
  //  |enabled_persistent_|=true   |enabled_|=false   |enabled_pending_|=true
  //
  // SetEnabled completes successfully, device is enabled:
  //  |enabled_persistent_|=true   |enabled_|=true    |enabled_pending_|=true
  //
  // User presses "Disable" button, SetEnabled(false) is called:
  //  |enabled_persistent_|=false   |enabled_|=true    |enabled_pending_|=false
  //
  // SetEnabled completes successfully, device is disabled:
  //  |enabled_persistent_|=false   |enabled_|=false    |enabled_pending_|=false
  bool enabled_;
  bool enabled_persistent_;
  bool enabled_pending_;

  std::string mac_address_;

  PropertyStore store_;

  const int interface_index_;
  const std::string link_name_;
  Manager* manager_;
  std::unique_ptr<DHCPController> dhcp_controller_;
  IPConfigRefPtr ipconfig_;
  IPConfigRefPtr ip6config_;
  std::unique_ptr<Connection> connection_;
  std::unique_ptr<DeviceAdaptorInterface> adaptor_;
  std::unique_ptr<PortalDetector> portal_detector_;
  // Callback to invoke when IPv6 DNS servers lifetime expired.
  base::CancelableClosure ipv6_dns_server_expired_callback_;
  // DNS servers obtained from ipconfig (either from DHCP or static config)
  // that are not working.
  std::vector<std::string> config_dns_servers_;
  Technology technology_;

  // Maintain a reference to the connected / connecting service
  ServiceRefPtr selected_service_;

  // Cache singleton pointers for performance and test purposes.
  DHCPProvider* dhcp_provider_;
  RoutingTable* routing_table_;
  RTNLHandler* rtnl_handler_;

  std::unique_ptr<PortalDetector> connection_tester_;

  // Track the current same-net multi-home state.
  bool is_multi_homed_;

  // If true, IP parameters should not be modified.
  bool fixed_ip_params_;

  // Remember which flag files were previously successfully written.
  std::set<std::string> written_flags_;

  std::unique_ptr<ConnectionDiagnostics> connection_diagnostics_;

  // See GetTrafficCountersCallback.
  unsigned int traffic_counter_callback_id_;

  // Maps the callback ID, created when FetchTrafficCounters is called, to the
  // corresponding callback.
  std::map<
      unsigned int,
      base::OnceCallback<void(const std::vector<patchpanel::TrafficCounter>&)>>
      traffic_counters_callback_map_;

  base::WeakPtrFactory<Device> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_DEVICE_H_
