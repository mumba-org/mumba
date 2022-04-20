// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MANAGER_H_
#define SHILL_MANAGER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "shill/connection.h"
#include "shill/default_service_observer.h"
#include "shill/device.h"
#include "shill/device_info.h"
#include "shill/event_dispatcher.h"
#include "shill/geolocation_info.h"
#include "shill/hook_table.h"
#include "shill/metrics.h"
#include "shill/mockable.h"
#include "shill/net/ip_address.h"
#include "shill/power_manager.h"
#include "shill/profile.h"
#include "shill/provider_interface.h"
#include "shill/service.h"
#include "shill/store/property_store.h"
#include "shill/upstart/upstart.h"

namespace shill {

class ControlInterface;
class DeviceClaimer;
class DefaultProfile;
class Error;
class EthernetProvider;
class EventDispatcher;
class ManagerAdaptorInterface;
class Resolver;
class VPNProvider;
class Throttler;

#if !defined(DISABLE_CELLULAR)
class CellularServiceProvider;
class ModemInfo;
#endif

#if !defined(DISABLE_WIFI)
class WiFiProvider;
#endif  // DISABLE_WIFI

#if !defined(DISABLE_WIRED_8021X)
class EthernetEapProvider;
#endif  // DISABLE_WIRED_8021X

#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
class SupplicantManager;
#endif  // !DISABLE_WIFI || !DISABLE_WIRED_8021X

// Helper class for storing in memory the set of shill Manager DBUS R or RW
// DBus properties.
// TODO(hugobenichi): simplify access patterns to the Manager properties and
// remove virtual mockable getter functions in Manager.
struct ManagerProperties {
  // Comma separated list of technologies for which portal detection is
  // enabled.
  std::string check_portal_list;
  // URL used for the first HTTP probe sent by PortalDetector on a new network
  // connection.
  std::string portal_http_url;
  // URL used for the first HTTPS probe sent by PortalDetector on a new
  // network connection.
  std::string portal_https_url;
  // Set of fallback URLs used for retrying the HTTP probe when portal
  // detection is not conclusive.
  std::vector<std::string> portal_fallback_http_urls;
  // Set of fallback URLs used for retrying the HTTPS probe when portal
  // detection is not conclusive.
  std::vector<std::string> portal_fallback_https_urls;
  // Whether to ARP for the default gateway in the DHCP client after
  // acquiring a lease.
  bool arp_gateway = true;
  // Comma-separated list of technologies for which auto-connect is disabled.
  std::string no_auto_connect_technologies;
  // Comma-separated list of technologies that should never be enabled.
  std::string prohibited_technologies;
  // Comma-separated list of DNS search paths to be ignored.
  std::string ignored_dns_search_paths;
  // The minimum MTU value that will be respected in DHCP responses.
  int minimum_mtu = IPConfig::kUndefinedMTU;
  // Name of Android VPN package that should be enforced for user traffic.
  // Empty string if the lockdown feature is not enabled.
  std::string always_on_vpn_package;
  // The IPv4 and IPv6 addresses of the DNS Proxy, if applicable. When these
  // values are set, resolv.conf should use these addresses as the name
  // servers.
  std::vector<std::string> dns_proxy_addresses;
  // Maps DNS-over-HTTPS service providers to a list of standard DNS name
  // servers. This member stores the value set via the DBus
  // |DNSProxyDOHProviders| property.
  KeyValueStore dns_proxy_doh_providers;
  // b/204261554: Controls if the new swanctl-based L2TPIPsecDriver should be
  // used instead of the legacy one based on ipsec script and stroke. This
  // property will be deprecated and removed when the migration is done.
  std::optional<bool> use_swanctl_driver;
  // Hostname to be used in DHCP request.
  std::string dhcp_hostname;

#if !defined(DISABLE_WIFI)
    std::optional<bool> ft_enabled;
    bool scan_allow_roam = true;
#endif  // !DISABLE_WIFI
};

class Manager {
 public:
  Manager(ControlInterface* control_interface,
          EventDispatcher* dispatcher,
          Metrics* metrics,
          const std::string& run_directory,
          const std::string& storage_directory,
          const std::string& user_storage_directory);
  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;

  virtual ~Manager();

  void RegisterAsync(const base::Callback<void(bool)>& completion_callback);

  mockable void OnDhcpPropertyChanged(const std::string& key,
                                      const std::string& value);

  virtual void SetBlockedDevices(
      const std::vector<std::string>& blockeded_devices);
  virtual void SetAllowedDevices(
      const std::vector<std::string>& allowed_devices);

  // Returns true if |device_name| is either not in the blocked list, or in the
  // allowed list, depending on which list was supplied in startup settings.
  virtual bool DeviceManagementAllowed(const std::string& device_name);

  virtual void Start();
  virtual void Stop();
  bool running() const { return running_; }

  // Requests for Services to be resorted; this method returns immediately
  // without actually performing the sorting.
  void SortServices();

  virtual const ProfileRefPtr& ActiveProfile() const;
  bool IsActiveProfile(const ProfileRefPtr& profile) const;
  virtual bool MoveServiceToProfile(const ServiceRefPtr& to_move,
                                    const ProfileRefPtr& destination);
  virtual bool MatchProfileWithService(const ServiceRefPtr& service);
  ProfileRefPtr LookupProfileByRpcIdentifier(const std::string& profile_rpcid);

  // Called via RPC call on Service (|to_set|) to set the "Profile" property.
  virtual void SetProfileForService(const ServiceRefPtr& to_set,
                                    const std::string& profile,
                                    Error* error);

  virtual void RegisterDevice(const DeviceRefPtr& to_manage);
  virtual void DeregisterDevice(const DeviceRefPtr& to_forget);

  virtual bool HasService(const ServiceRefPtr& service);
  // Register a Service with the Manager. Manager may choose to
  // connect to it immediately.
  virtual void RegisterService(const ServiceRefPtr& to_manage);
  // Deregister a Service from the Manager. Caller is responsible
  // for disconnecting the Service before-hand.
  virtual void DeregisterService(const ServiceRefPtr& to_forget);
  virtual void UpdateService(const ServiceRefPtr& to_update);
  // Called when any service's state changes.  Informs other services
  // (e.g. VPNs) if the default physical service's state has changed.
  virtual void NotifyServiceStateChanged(const ServiceRefPtr& to_update);

  // Persists |to_update| into an appropriate profile.
  virtual void UpdateDevice(const DeviceRefPtr& to_update);

  std::vector<DeviceRefPtr> FilterByTechnology(Technology tech) const;

  RpcIdentifiers EnumerateAvailableServices(Error* error);

  // Return the complete list of services, including those that are not visible.
  RpcIdentifiers EnumerateCompleteServices(Error* error);

  // called via RPC (e.g., from ManagerDBusAdaptor)
  std::map<RpcIdentifier, std::string> GetLoadableProfileEntriesForService(
      const ServiceConstRefPtr& service);
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error);
  ServiceRefPtr ConfigureService(const KeyValueStore& args, Error* error);
  ServiceRefPtr ConfigureServiceForProfile(const std::string& profile_rpcid,
                                           const KeyValueStore& args,
                                           Error* error);
  ServiceRefPtr FindMatchingService(const KeyValueStore& args, Error* error);

  // Return the Device that has selected this Service. If no Device has selected
  // this Service or the Service pointer is null, return nullptr. Note that
  // VirtualDevices which are not managed by Manager will also be included here.
  virtual DeviceRefPtr FindDeviceFromService(
      const ServiceRefPtr& service) const;

  // It the service has an active connection, returns the Connection object
  // associated with the Device which has selected this Service. This pointer is
  // owned by Device and thus cannot be held. Returns nullptr if no such
  // Connection or the Service pointer is null.
  Connection* FindConnectionFromService(const ServiceRefPtr& service) const;

  // Return the highest priority service of a physical technology type (i.e. not
  // VPN, ARC, etc), or nullptr if no such service is found.
  virtual ServiceRefPtr GetPrimaryPhysicalService();
  // Return the first service of type |Technology::kEthernet| found in
  // |services_|, or nullptr if no such service is found.
  virtual ServiceRefPtr GetFirstEthernetService();

  // Retrieve geolocation data from the Manager.
  std::map<std::string, std::vector<GeolocationInfo>>
  GetNetworksForGeolocation() const;

  // Called by Device when its geolocation data has been updated.
  virtual void OnDeviceGeolocationInfoUpdated(const DeviceRefPtr& device);

  // Force a wifi scan if applicable, and connect to the best available
  // services.
  // Called by chrome when a user profile is loaded and the user's
  // policy-provided networks are configured.
  void ScanAndConnectToBestServices(Error* error);

  // Connects to the highest priority service for each available technology.
  // Note: ConnectToBestServices should only be called from
  // ScanAndConnectToBestServices.
  // All other calls should be considered deprecated.  This method should be
  // removed eventually (b:206907629).
  virtual void ConnectToBestServices(Error* error);

  // Method to create connectivity report for connected services.
  void CreateConnectivityReport(Error* error);

  // Request portal detection checks on each registered device with a connected
  // Service.
  void RecheckPortal(Error* error);
  // Request portal detection be restarted on the device connected to
  // |service|.
  virtual void RecheckPortalOnService(const ServiceRefPtr& service);

  virtual void RequestScan(const std::string& technology, Error* error);
  std::string GetTechnologyOrder();
  virtual void SetTechnologyOrder(const std::string& order, Error* error);
  // Set up the profile list starting with a default profile along with
  // an (optional) list of startup profiles.
  void InitializeProfiles();
  // Create a profile.  This does not affect the profile stack.  Returns
  // the RPC path of the created profile in |path|.
  void CreateProfile(const std::string& name, std::string* path, Error* error);
  // Pushes existing profile with name |name| onto stack of managed profiles.
  // Returns the RPC path of the pushed profile in |path|.
  void PushProfile(const std::string& name, std::string* path, Error* error);
  // Insert an existing user profile with name |name| into the stack of
  // managed profiles.  Associate |user_hash| with this profile entry.
  // Returns the RPC path of the pushed profile in |path|.
  void InsertUserProfile(const std::string& name,
                         const std::string& user_hash,
                         std::string* path,
                         Error* error);
  // Pops profile named |name| off the top of the stack of managed profiles.
  void PopProfile(const std::string& name, Error* error);
  // Remove the active profile.
  void PopAnyProfile(Error* error);
  // Remove all user profiles from the stack of managed profiles leaving only
  // default profiles.
  void PopAllUserProfiles(Error* error);
  // Remove the underlying persistent storage for a profile.
  void RemoveProfile(const std::string& name, Error* error);
  // Called by a profile when its properties change.
  void OnProfileChanged(const ProfileRefPtr& profile);
  // Give the ownership of the device with name |device_name| to claimer with
  // name |claimer_name|. This will cause shill to stop managing this device.
  virtual void ClaimDevice(const std::string& claimer_name,
                           const std::string& interface_name,
                           Error* error);
  // Claimer |claimer_name| release the ownership of the device with
  // |interface_name| back to shill. This method will set |claimer_removed|
  // to true iff Claimer |claimer_name| is not the default claimer and no
  // longer claims any devices.
  virtual void ReleaseDevice(const std::string& claimer_name,
                             const std::string& interface_name,
                             bool* claimer_removed,
                             Error* error);

  // Called by a service to remove its associated configuration.  If |service|
  // is associated with a non-ephemeral profile, this configuration entry
  // will be removed and the manager will search for another matching profile.
  // If the service ends up with no matching profile, it is unloaded (which
  // may also remove the service from the manager's list, e.g. WiFi services
  // that are not visible)..
  virtual void RemoveService(const ServiceRefPtr& service);
  // Handle the event where a profile is about to remove a profile entry.
  // Any Services that are dependent on this storage identifier will need
  // to find new profiles.  Return true if any service has been moved to a new
  // profile.  Any such services will have had the profile group removed from
  // the profile.
  virtual bool HandleProfileEntryDeletion(const ProfileRefPtr& profile,
                                          const std::string& entry_name);
  // Find a registered service that contains a GUID property that
  // matches |guid|.
  virtual ServiceRefPtr GetServiceWithGUID(const std::string& guid,
                                           Error* error);
  // Find a service that has a storage identifier that matches |entry_name|.
  virtual ServiceRefPtr GetServiceWithStorageIdentifier(
      const std::string& entry_name);
  // Find a service that is both the member of |profile| and has a
  // storage identifier that matches |entry_name|.  This function is
  // called by the Profile in order to return a profile entry's properties.
  virtual ServiceRefPtr GetServiceWithStorageIdentifierFromProfile(
      const ProfileRefPtr& profile,
      const std::string& entry_name,
      Error* error);
  // Find a service that has a RpcIdentifier that matches |id|.
  virtual ServiceRefPtr GetServiceWithRpcIdentifier(const RpcIdentifier& id);
  // Create a temporary service for an entry |entry_name| within |profile|.
  // Callers must not register this service with the Manager or connect it
  // since it was never added to the provider's service list.
  virtual ServiceRefPtr CreateTemporaryServiceFromProfile(
      const ProfileRefPtr& profile,
      const std::string& entry_name,
      Error* error);
  // Return a reference to the Service associated with the default connection.
  // If there is no such connection, this function returns a reference to NULL.
  virtual ServiceRefPtr GetDefaultService() const;
  RpcIdentifier GetDefaultServiceRpcIdentifier(Error* error);

  // Set enabled state of all |technology_name| devices to |enabled_state|.
  // Persist the state to storage is |persist| is true.
  void SetEnabledStateForTechnology(const std::string& technology_name,
                                    bool enabled_state,
                                    bool persist,
                                    const ResultCallback& callback);
  // Return whether a technology is marked as enabled for portal detection.
  virtual bool IsPortalDetectionEnabled(Technology tech);
  // Set the start-up value for the portal detection list.  This list will
  // be used until a value set explicitly over the control API.  Until
  // then, we ignore but do not overwrite whatever value is stored in the
  // profile.
  virtual void SetStartupPortalList(const std::string& portal_list);

  // Returns true if profile |a| has been pushed on the Manager's
  // |profiles_| stack before profile |b|.
  virtual bool IsProfileBefore(const ProfileRefPtr& a,
                               const ProfileRefPtr& b) const;

  // Return whether a service belongs to the ephemeral profile.
  virtual bool IsServiceEphemeral(const ServiceConstRefPtr& service) const;

  // Return whether a Technology has any connected Services.
  virtual bool IsTechnologyConnected(Technology technology) const;

  // Return whether the Wake on LAN feature is enabled.
  virtual bool IsWakeOnLanEnabled() const { return is_wake_on_lan_enabled_; }

  // Return whether a technology is disabled for auto-connect.
  virtual bool IsTechnologyAutoConnectDisabled(Technology technology) const;

  // Report whether |technology| is prohibited from being enabled.
  virtual bool IsTechnologyProhibited(Technology technology) const;

  // Called by Profile when a |storage| completes initialization.
  void OnProfileStorageInitialized(Profile* storage);

  // Return a Device with technology |technology| in the enabled state.
  virtual DeviceRefPtr GetEnabledDeviceWithTechnology(
      Technology technology) const;

  // Returns true if at least one connection exists, and false if there's no
  // connected service.
  virtual bool IsConnected() const;
  // Returns true if at least one connection exists that have Internet
  // connectivity, and false if there's no such service.
  virtual bool IsOnline() const;
  std::string CalculateState(Error* error);

  // Recalculate the |connected_state_| string and emit a singal if it has
  // changed.
  void RefreshConnectionState();

  virtual DeviceInfo* device_info() { return &device_info_; }
#if !defined(DISABLE_CELLULAR)
  virtual ModemInfo* modem_info() { return modem_info_.get(); }
  virtual CellularServiceProvider* cellular_service_provider() {
    return cellular_service_provider_.get();
  }
#endif  // DISABLE_CELLULAR
  PowerManager* power_manager() const { return power_manager_.get(); }
  virtual EthernetProvider* ethernet_provider() {
    return ethernet_provider_.get();
  }
#if !defined(DISABLE_WIRED_8021X)
  virtual EthernetEapProvider* ethernet_eap_provider() const {
    return ethernet_eap_provider_.get();
  }
#endif  // DISABLE_WIRED_8021X
  VPNProvider* vpn_provider() const { return vpn_provider_.get(); }
#if !defined(DISABLE_WIFI)
  WiFiProvider* wifi_provider() const { return wifi_provider_.get(); }
#endif  // DISABLE_WIFI
  PropertyStore* mutable_store() { return &store_; }
  virtual const PropertyStore& store() const { return store_; }
  virtual const base::FilePath& run_path() const { return run_path_; }
  const base::FilePath& storage_path() const { return storage_path_; }

  const base::ObserverList<DefaultServiceObserver>& default_service_observers()
      const {
    return default_service_observers_;
  }

  virtual int64_t GetSuspendDurationUsecs() const {
    return power_manager_->suspend_duration_us();
  }

  virtual const ManagerProperties& GetProperties() const { return props_; }

  bool GetArpGateway() const { return props_.arp_gateway; }

  virtual int GetMinimumMTU() const { return props_.minimum_mtu; }

  virtual void SetMinimumMTU(const int mtu) { props_.minimum_mtu = mtu; }

  virtual void UpdateEnabledTechnologies();
  virtual void UpdateUninitializedTechnologies();

  virtual const std::string& dhcp_hostname() const {
    return props_.dhcp_hostname;
  }

  // Writes the Service |to_update| to persistent storage. If the Service is
  // ephemeral, it is moved to the current Profile.
  void PersistService(const ServiceRefPtr& to_update);

  // Adds a closure to be executed when ChromeOS suspends or shill terminates.
  // |name| should be unique; otherwise, a previous closure by the same name
  // will be replaced.  |start| will be called when RunTerminationActions() is
  // called.  When an action completed, TerminationActionComplete() must be
  // called.
  void AddTerminationAction(const std::string& name,
                            const base::Closure& start);

  // Users call this function to report the completion of an action |name|.
  // This function should be called once for each action.
  void TerminationActionComplete(const std::string& name);

  // Removes the action associtated with |name|.
  void RemoveTerminationAction(const std::string& name);

  // Runs the termination actions and notifies the metrics framework
  // that the termination actions started running, only if any termination
  // actions have been registered. If all actions complete within
  // |kTerminationActionsTimeoutMilliseconds|, |done_callback| is called with a
  // value of Error::kSuccess. Otherwise, it is called with
  // Error::kOperationTimeout.
  //
  // Returns true, if termination actions were run.
  bool RunTerminationActionsAndNotifyMetrics(
      const ResultCallback& done_callback);

  // Add/remove observers to subscribe to default Service notifications.
  void AddDefaultServiceObserver(DefaultServiceObserver* observer);
  void RemoveDefaultServiceObserver(DefaultServiceObserver* observer);

  // Running in passive mode, manager will not manage any devices (all devices
  // are blocked) by default. Remote application can specify devices for
  // shill to manage through ReleaseInterface/ClaimInterface DBus API using
  // default claimer (with "" as claimer_name).
  virtual void SetPassiveMode();

  // Decides whether Ethernet-like devices are treated as unknown devices
  // if they do not indicate a driver name.
  virtual void SetIgnoreUnknownEthernet(bool ignore);
  virtual bool ignore_unknown_ethernet() const {
    return ignore_unknown_ethernet_;
  }

  // Accept hostname from DHCP server for devices matching |hostname_from|.
  virtual void SetAcceptHostnameFrom(const std::string& hostname_from);
  virtual bool ShouldAcceptHostnameFrom(const std::string& device_name) const;

  // Returns true iff |power_manager_| exists and is suspending (i.e.
  // power_manager->suspending() is true), false otherwise.
  virtual bool IsSuspending();

  // Called when service's inner device changed.
  virtual void OnInnerDevicesChanged();

  void set_suppress_autoconnect(bool val) { suppress_autoconnect_ = val; }
  bool suppress_autoconnect() const { return suppress_autoconnect_; }

  // Called when remote device claimer vanishes.
  virtual void OnDeviceClaimerVanished();

  RpcIdentifiers EnumerateDevices(Error* error);

  bool SetNetworkThrottlingStatus(const ResultCallback& callback,
                                  bool enabled,
                                  uint32_t upload_rate_kbits,
                                  uint32_t download_rate_kbits);

  // Returns the interface names associated with 'real' devices
  // on the system e.g. eth0, wlan0.
  virtual std::vector<std::string> GetDeviceInterfaceNames();

#if !defined(DISABLE_WIFI)
  bool GetFTEnabled(Error* error);
  bool scan_allow_roam() const { return props_.scan_allow_roam; }
#endif  // DISABLE_WIFI

  bool ShouldBlackholeUserTraffic(const std::string& device_name) const;

  // Returns whether the swanctl-based driver should be used.
  bool GetUseSwanctlDriver(Error* error);

  // Returns the user traffic uids.
  const std::vector<uint32_t>& GetUserTrafficUids();

  ControlInterface* control_interface() const { return control_interface_; }
  EventDispatcher* dispatcher() const { return dispatcher_; }
  Metrics* metrics() const { return metrics_; }
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  SupplicantManager* supplicant_manager() const {
    return supplicant_manager_.get();
  }
#endif  // !DISABLE_WIFI || !DISABLE_WIRED_8021X
  void set_patchpanel_client_for_testing(
      std::unique_ptr<patchpanel::Client> patchpanel_client) {
    patchpanel_client_ = std::move(patchpanel_client);
  }
  patchpanel::Client* patchpanel_client() { return patchpanel_client_.get(); }

  // Returns a vector of all uids whose traffic is routed through VPN
  // connections.
  static std::vector<uint32_t> ComputeUserTrafficUids();

  // Assigns the IP address(es) of the dns-proxy service.
  bool SetDNSProxyAddresses(const std::vector<std::string>& addrs,
                            Error* error);

  // Clears the IP address of the dns-proxy service.
  void ClearDNSProxyAddresses();

  // Assigns the DNS-over-HTTPS service providers for use by the dns-proxy
  // service.
  bool SetDNSProxyDOHProviders(const KeyValueStore& providers, Error* error);

  // Creates a set of Passpoint credentials from |properties| in the profile
  // referenced by |profile_id|.
  bool AddPasspointCredentials(const std::string& profile_rpcid,
                               const KeyValueStore& properties,
                               Error* error);

  // Removes all Passpoint credentials that matches all property of |properties|
  // in the profile referenced by |profile_id|.
  bool RemovePasspointCredentials(const std::string& profile_rpcid,
                                  const KeyValueStore& properties,
                                  Error* error);

 private:
  friend class ArcVpnDriverTest;
  friend class CellularTest;
  friend class DeviceInfoTest;
  friend class DeviceTest;
  friend class L2TPIPsecDriverTest;
  friend class ManagerAdaptorInterface;
  friend class ManagerTest;
  friend class ModemInfoTest;
  friend class ModemManagerTest;
  friend class OpenVPNDriverTest;
  friend class ServiceTest;
  friend class VPNServiceTest;
  friend class WiFiObjectTest;

  FRIEND_TEST(CellularCapability3gppTest, TerminationAction);
  FRIEND_TEST(CellularCapability3gppTest, TerminationActionRemovedByStopModem);
  FRIEND_TEST(CellularTest, LinkEventWontDestroyService);
  FRIEND_TEST(DefaultProfileTest, LoadManagerDefaultProperties);
  FRIEND_TEST(DefaultProfileTest, LoadManagerProperties);
  FRIEND_TEST(DefaultProfileTest, Save);
  FRIEND_TEST(DeviceInfoTest, CreateDeviceEthernet);
  FRIEND_TEST(DeviceTest, StartProhibited);
  FRIEND_TEST(ManagerTest, AvailableTechnologies);
  FRIEND_TEST(ManagerTest, ClaimBlockedDevice);
  FRIEND_TEST(ManagerTest, ClaimDeviceWithoutClaimer);
  FRIEND_TEST(ManagerTest, ConnectedTechnologies);
  FRIEND_TEST(ManagerTest, ConnectionStatusCheck);
  FRIEND_TEST(ManagerTest, ConnectToBestServices);
  FRIEND_TEST(ManagerTest, CreateConnectivityReport);
  FRIEND_TEST(ManagerTest, DefaultTechnology);
  FRIEND_TEST(ManagerTest, DefaultServiceStateChange);
  FRIEND_TEST(ManagerTest, DetectMultiHomedDevices);
  FRIEND_TEST(ManagerTest, DevicePresenceStatusCheck);
  FRIEND_TEST(ManagerTest, DeviceRegistrationAndStart);
  FRIEND_TEST(ManagerTest, DeviceRegistrationTriggersThrottler);
  FRIEND_TEST(ManagerTest, EnumerateProfiles);
  FRIEND_TEST(ManagerTest, EnumerateServiceInnerDevices);
  FRIEND_TEST(ManagerTest, InitializeProfilesInformsProviders);
  FRIEND_TEST(ManagerTest, InitializeProfilesHandlesDefaults);
  FRIEND_TEST(ManagerTest, IsTechnologyAutoConnectDisabled);
  FRIEND_TEST(ManagerTest, IsTechnologyProhibited);
  FRIEND_TEST(ManagerTest, IsWifiIdle);
  FRIEND_TEST(ManagerTest, LinkMonitorEnabled);
  FRIEND_TEST(ManagerTest, MoveService);
  FRIEND_TEST(ManagerTest, UpdateDefaultServices);
  FRIEND_TEST(ManagerTest, UpdateDefaultServicesDNSProxy);
  FRIEND_TEST(ManagerTest,
              UpdateDefaultServicesWithDefaultServiceCallbacksRemoved);
  FRIEND_TEST(ManagerTest, UpdateBlackholeUserTraffic);
  FRIEND_TEST(ManagerTest, RefreshAllTrafficCountersTask);
  FRIEND_TEST(ManagerTest, RegisterKnownService);
  FRIEND_TEST(ManagerTest, RegisterUnknownService);
  FRIEND_TEST(ManagerTest, ReleaseBlockedDevice);
  FRIEND_TEST(ManagerTest, RunTerminationActions);
  FRIEND_TEST(ManagerTest, ServiceRegistration);
  FRIEND_TEST(ManagerTest, SetAlwaysOnVpnPackage);
  FRIEND_TEST(ManagerTest, ShouldBlackholeUserTraffic);
  FRIEND_TEST(ManagerTest, SortServicesWithConnection);
  FRIEND_TEST(ManagerTest, StartupPortalList);
  FRIEND_TEST(ManagerTest, SetDNSProxyAddresses);
  FRIEND_TEST(ServiceTest, IsAutoConnectable);
  FRIEND_TEST(ThirdPartyVpnDriverTest, SetParameters);
  FRIEND_TEST(VPNProviderTest, SetDefaultRoutingPolicy);
  FRIEND_TEST(WiFiServiceTest, ConnectTaskFT);
  FRIEND_TEST(WiFiMainTest, ScanAllowRoam);

  void AutoConnect();
  // Ensure always-on VPN follows the current configuration, ie: hardware
  // connectivity is available and the correct VPN service is running.
  void ApplyAlwaysOnVpn(const ServiceRefPtr& physical_service);
  // Update always-on VPN configuration with the one contained in |profile|.
  void UpdateAlwaysOnVpnWith(const ProfileRefPtr& profile);
  // Set the always-on VPN configuration and start or stop VPN lockdown if
  // needed.
  void SetAlwaysOnVpn(const std::string& mode, VPNServiceRefPtr service);
  // Connect the always-on VPN and maintain the previous connection attempts
  // count.
  void ConnectAlwaysOnVpn();
  // Reset the connection backoff to its initial state.  Used on a successful
  // attempt or a physical network change for instance.
  void ResetAlwaysOnVpnBackoff();
  bool IsServiceAlwaysOnVpn(const ServiceConstRefPtr& service) const;
  std::vector<std::string> AvailableTechnologies(Error* error);
  std::vector<std::string> ConnectedTechnologies(Error* error);
  std::string DefaultTechnology(Error* error);
  std::vector<std::string> EnabledTechnologies(Error* error);
  std::vector<std::string> UninitializedTechnologies(Error* error);
  RpcIdentifiers EnumerateProfiles(Error* error);
  RpcIdentifiers EnumerateWatchedServices(Error* error);
  RpcIdentifier GetActiveProfileRpcIdentifier(Error* error);
  std::string GetCheckPortalList(Error* error);
  std::string GetIgnoredDNSSearchPaths(Error* error);
  std::string GetPortalFallbackUrlsString(Error* error);
  ServiceRefPtr GetServiceInner(const KeyValueStore& args, Error* error);
  bool SetAlwaysOnVpnPackage(const std::string& package_name, Error* error);
  bool SetCheckPortalList(const std::string& portal_list, Error* error);
  bool SetIgnoredDNSSearchPaths(const std::string& ignored_paths, Error* error);
  bool SetPortalFallbackUrlsString(const std::string& urls, Error* error);
  // Emit a kDefaultServiceProperty property-changed D-Bus signal if the default
  // Service has changed. Returns true only if the default Service did actually
  // change.
  bool EmitDefaultService();
  bool IsTechnologyInList(const std::string& technology_list,
                          Technology tech) const;
  void EmitDeviceProperties();
#if !defined(DISABLE_WIFI)
  bool SetDisableWiFiVHT(const bool& disable_wifi_vht, Error* error);
  bool GetDisableWiFiVHT(Error* error);

  bool SetFTEnabled(const bool& ft_enabled, Error* error);
#endif  // DISABLE_WIFI
  bool SetProhibitedTechnologies(const std::string& prohibited_technologies,
                                 Error* error);
  std::string GetProhibitedTechnologies(Error* error);
  void OnTechnologyProhibited(Technology technology, const Error& error);
  bool SetUseSwanctlDriver(const bool& use_swanctl_driver, Error* error);

  void UseDNSProxy(const std::vector<std::string>& proxy_addrs);

  KeyValueStore GetDNSProxyDOHProviders(Error* error);

  // For every device instance that is sharing the same connectivity with
  // another device, enable the multi-home flag.
  void DetectMultiHomedDevices();

  // Unload a service while iterating through |services_|.  Returns true if
  // service was erased (which means the caller loop should not increment
  // |service_iterator|), false otherwise (meaning the caller should
  // increment |service_iterator|).
  bool UnloadService(std::vector<ServiceRefPtr>::iterator* service_iterator);

  // Load Manager default properties from |profile|.
  void LoadProperties(const scoped_refptr<DefaultProfile>& profile);

  // Configure the device with profile data from all current profiles.
  void LoadDeviceFromProfiles(const DeviceRefPtr& device);

  void HelpRegisterConstDerivedRpcIdentifier(
      const std::string& name, RpcIdentifier (Manager::*get)(Error*));
  void HelpRegisterConstDerivedRpcIdentifiers(
      const std::string& name, RpcIdentifiers (Manager::*get)(Error*));
  void HelpRegisterDerivedString(const std::string& name,
                                 std::string (Manager::*get)(Error* error),
                                 bool (Manager::*set)(const std::string&,
                                                      Error*));
  void HelpRegisterConstDerivedStrings(const std::string& name,
                                       Strings (Manager::*get)(Error*));
  void HelpRegisterDerivedKeyValueStore(
      const std::string& name,
      KeyValueStore (Manager::*get)(Error* error),
      bool (Manager::*set)(const KeyValueStore& value, Error* error));
  void HelpRegisterDerivedBool(const std::string& name,
                               bool (Manager::*get)(Error* error),
                               bool (Manager::*set)(const bool& value,
                                                    Error* error));

  bool HasProfile(const Profile::Identifier& ident);
  void PushProfileInternal(const Profile::Identifier& ident,
                           std::string* path,
                           Error* error);
  void PopProfileInternal();
  void OnProfilesChanged();

  void SortServicesTask();
  void DeviceStatusCheckTask();
  void ConnectionStatusCheck();
  void DevicePresenceStatusCheck();

  // Sets the profile of |service| to |profile|, without notifying its
  // previous profile.  Configures a |service| with |args|, then saves
  // the resulting configuration to |profile|.  This method is useful
  // when copying a service configuration from one profile to another,
  // or writing a newly created service config to a specific profile.
  static void SetupServiceInProfile(ServiceRefPtr service,
                                    ProfileRefPtr profile,
                                    const KeyValueStore& args,
                                    Error* error);

  // For each technology present, connect to the "best" service available,
  // as determined by sorting all services independent of their current state.
  void ConnectToBestServicesTask();

  void UpdateDefaultServices(const ServiceRefPtr& logical_service,
                             const ServiceRefPtr& physical_service);

  // Runs the termination actions.  If all actions complete within
  // |kTerminationActionsTimeoutMilliseconds|, |done_callback| is called with a
  // value of Error::kSuccess.  Otherwise, it is called with
  // Error::kOperationTimeout.
  void RunTerminationActions(const ResultCallback& done_callback);

  // Called when the system is about to be suspended.  Each call will be
  // followed by a call to OnSuspendDone().
  void OnSuspendImminent();

  // Called when the system has completed a suspend attempt (possibly without
  // actually suspending, in the event of the user canceling the attempt).
  void OnSuspendDone();

  // Called when the system is entering a dark resume phase (and hence a dark
  // suspend is imminent).
  void OnDarkSuspendImminent();

  void OnSuspendActionsComplete(const Error& error);
  void OnDarkResumeActionsComplete(const Error& error);

  // Return true if wifi device is enabled with no existing connection (pending
  // or connected).
  bool IsWifiIdle();

  // For unit testing.
  void set_metrics(Metrics* metrics) { metrics_ = metrics; }
  void UpdateProviderMapping();

  // Used by tests to set a mock PowerManager.  Takes ownership of
  // power_manager.
  void set_power_manager(PowerManager* power_manager) {
    power_manager_.reset(power_manager);
  }

  DeviceRefPtr GetDeviceConnectedToService(ServiceRefPtr service);

  void DeregisterDeviceByLinkName(const std::string& link_name);

  std::string GetAlwaysOnVpnPackage(Error* error);

  void UpdateBlackholeUserTraffic();

  // Initializes patchpanel_client_ if it has not already been initialized.
  void InitializePatchpanelClient();

  void RefreshAllTrafficCountersCallback(
      const std::vector<patchpanel::TrafficCounter>& counters);
  void RefreshAllTrafficCountersTask();

  // Returns the names of all of the devices that have been claimed by the
  // current DeviceClaimer.  Returns an empty vector if no DeviceClaimer is set.
  std::vector<std::string> ClaimedDevices(Error* error);

  EventDispatcher* dispatcher_;
  ControlInterface* control_interface_;
  Metrics* metrics_;

  const base::FilePath run_path_;
  const base::FilePath storage_path_;
  const base::FilePath user_storage_path_;
  base::FilePath user_profile_list_path_;  // Changed in tests.
  std::unique_ptr<ManagerAdaptorInterface> adaptor_;
  DeviceInfo device_info_;
#if !defined(DISABLE_CELLULAR)
  std::unique_ptr<ModemInfo> modem_info_;
  std::unique_ptr<CellularServiceProvider> cellular_service_provider_;
#endif  // DISABLE_CELLULAR
  std::unique_ptr<EthernetProvider> ethernet_provider_;
#if !defined(DISABLE_WIRED_8021X)
  std::unique_ptr<EthernetEapProvider> ethernet_eap_provider_;
#endif  // DISABLE_WIRED_8021X
  std::unique_ptr<VPNProvider> vpn_provider_;
#if !defined(DISABLE_WIFI)
  std::unique_ptr<WiFiProvider> wifi_provider_;
#endif  // DISABLE_WIFI
#if !defined(DISABLE_WIFI) || !defined(DISABLE_WIRED_8021X)
  std::unique_ptr<SupplicantManager> supplicant_manager_;
#endif  // !DISABLE_WIFI || !DISABLE_WIRED_8021X
  // For communication with patchpanel.
  std::unique_ptr<patchpanel::Client> patchpanel_client_;

  // Entity that calls kernel commands ('tc') to throttle network bandwidth.
  std::unique_ptr<Throttler> throttler_;

  // Hold pointer to singleton Resolver instance for testing purposes.
  Resolver* resolver_;
  bool running_;
  std::vector<DeviceRefPtr> devices_;
  // We store Services in a vector, because we want to keep them sorted.
  // Services that are connected appear first in the vector.  See
  // Service::Compare() for details of the sorting criteria.
  std::vector<ServiceRefPtr> services_;
  // Last known default physical service (i.e. not a VPN).  Used to figure
  // out when to send the DefaultServiceChanged notification.
  ServiceRefPtr last_default_physical_service_;
  bool last_default_physical_service_online_;
  // Current always-on VPN operating mode.
  std::string always_on_vpn_mode_;
  // Reference to the VPN service managed by always-on VPN.  It may reference
  // nothing if there's no service configured, otherwise it heads to a
  // VPNService.
  VPNServiceRefPtr always_on_vpn_service_;
  // Count of always-on VPN service connection attempts since the last reset.
  uint32_t always_on_vpn_connect_attempts_;
  // Task to connect always-on VPN service.
  base::CancelableClosure always_on_vpn_connect_task_;
  // Map of technologies to Provider instances.  These pointers are owned
  // by the respective scoped_reptr objects that are held over the lifetime
  // of the Manager object.
  std::map<Technology, ProviderInterface*> providers_;
  // List of startup profile names to push on the profile stack on startup.
  std::vector<ProfileRefPtr> profiles_;
  ProfileRefPtr ephemeral_profile_;
  std::unique_ptr<PowerManager> power_manager_;
  std::unique_ptr<Upstart> upstart_;

  // The priority order of technologies
  std::vector<Technology> technology_order_;

  // This is the last Service RPC Identifier for which we emitted a
  // "DefaultService" signal for.
  RpcIdentifier default_service_rpc_identifier_;

  // Manager can be optionally configured with a list of technologies to
  // do portal detection on at startup.  We need to keep track of that list
  // as well as a flag that tells us whether we should continue using it
  // instead of the configured portal list.
  std::string startup_portal_list_;
  bool use_startup_portal_list_;

  // Properties to be get/set via PropertyStore calls.
  ManagerProperties props_;
  PropertyStore store_;

  // Accept hostname supplied by the DHCP server from the specified devices.
  // eg. eth0 or eth*
  std::string accept_hostname_from_;

  base::CancelableClosure sort_services_task_;

  // Task for periodically checking various device status.
  base::CancelableClosure device_status_check_task_;

  // Task for initializing patchpanel connection.
  base::CancelableClosure init_patchpanel_client_task_;

  // Task for periodically refreshing traffic counters.
  base::CancelableClosure refresh_traffic_counter_task_;

  // Whether we're currently waiting on a traffic counter fetch from patchpanel.
  bool pending_traffic_counter_request_;

  // Actions to take when shill is terminating.
  HookTable termination_actions_;

  // Whether Wake on LAN should be enabled for all Ethernet devices.
  bool is_wake_on_lan_enabled_;

  // Whether to ignore Ethernet-like devices that don't have an assigned driver.
  bool ignore_unknown_ethernet_;

  // List of DefaultServiceObservers registered with AddDefaultServiceObserver.
  base::ObserverList<DefaultServiceObserver> default_service_observers_;

  // Stores the most recent copy of geolocation information for each
  // device the manager is keeping track of.
  std::map<DeviceRefPtr, std::vector<GeolocationInfo>> device_geolocation_info_;

  // Stores the state of the highest ranked connected service.
  std::string connection_state_;

  // Stores the most recent state of all watched services by serial number.
  std::map<unsigned int, Service::ConnectState> watched_service_states_;

  // Device claimer is a remote application/service that claim/release devices
  // from/to shill. To reduce complexity, only allow one device claimer at a
  // time.
  std::unique_ptr<DeviceClaimer> device_claimer_;

  // When true, suppresses autoconnects in Manager::AutoConnect.
  bool suppress_autoconnect_;

  // Whether any of the services is in connected state or not.
  bool is_connected_state_;

  // Set to true if there is a user session, which is inferred based on calls
  // to Manager::InsertUserProfile() and Manager::PopAllUserProfiles().
  bool has_user_session_;

  // List of blocked devices specified from command line.
  std::vector<std::string> blocked_devices_;

  // List of allowed devices specified from command line.
  std::vector<std::string> allowed_devices_;

  // List of supported vpn types;
  std::string supported_vpn_;

  // Bandwidth throttling variables. Default values are overridden by
  // SetNetworkThrottlingStatus, called from the client.
  bool network_throttling_enabled_;
  uint32_t download_rate_kbits_;
  uint32_t upload_rate_kbits_;

  // "User traffic" refers to traffic from processes that run under one of the
  // unix users enumered in |kUserTrafficUsernames| constant in
  // shill/manager.cc.
  bool should_blackhole_user_traffic_;
  std::vector<uint32_t> user_traffic_uids_;
  base::WeakPtrFactory<Manager> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_MANAGER_H_
