// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_SERVICE_H_
#define SHILL_WIFI_WIFI_SERVICE_H_

#include <limits>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/time/clock.h>
#include <base/time/time.h>
#include <base/time/default_clock.h>

#include "shill/event_dispatcher.h"
#include "shill/mac_address.h"
#include "shill/metrics.h"
#include "shill/mockable.h"
#include "shill/refptr_types.h"
#include "shill/service.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

class CertificateFile;
class Error;
class Manager;
class PasspointCredentials;
class WiFiProvider;

class WiFiService : public Service {
 public:
  // TODO(pstew): Storage constants shouldn't need to be public
  // crbug.com/208736
  static const char kStorageCredentialPassphrase[];
  static const char kStorageHiddenSSID[];
  static const char kStorageMode[];
  static const char kStorageSecurityClass[];
  static const char kStorageSSID[];
  static const char kStoragePasspointCredentials[];
  static const char kStoragePasspointMatchPriority[];

  // Default signal level value without any endpoint.
  static const int16_t SignalLevelMin = std::numeric_limits<int16_t>::min();

  // Enumeration of supported randomization policies.
  enum class RandomizationPolicy : uint16_t {
    Hardware = 0,      // Use hardware MAC address.
    FullRandom,        // Change whole MAC every time we associate.
    OUIRandom,         // Change non-OUI MAC part every time we associate.
    PersistentRandom,  // Set per-SSID/profile persistent MAC.
    // Contrary to previous values, NonPersistentRandom has no equivalent in
    // WPA Supplicant. PersistentRandom with non-persistent MAC is used there.
    NonPersistentRandom,
  };

  WiFiService(Manager* manager,
              WiFiProvider* provider,
              const std::vector<uint8_t>& ssid,
              const std::string& mode,
              const std::string& security_class,
              bool hidden_ssid);
  WiFiService(const WiFiService&) = delete;
  WiFiService& operator=(const WiFiService&) = delete;

  ~WiFiService();

  // Inherited from Service.
  bool Is8021x() const override;

  mockable void AddEndpoint(const WiFiEndpointConstRefPtr& endpoint);
  mockable void RemoveEndpoint(const WiFiEndpointConstRefPtr& endpoint);
  mockable int GetEndpointCount() const { return endpoints_.size(); }

  // Called to update the identity of the currently connected endpoint.
  // To indicate that there is no currently connect endpoint, call with
  // |endpoint| set to nullptr.
  mockable void NotifyCurrentEndpoint(const WiFiEndpointConstRefPtr& endpoint);
  // Called to inform of changes in the properties of an endpoint.
  // (Not necessarily the currently connected endpoint.)
  mockable void NotifyEndpointUpdated(const WiFiEndpointConstRefPtr& endpoint);

  // wifi_<MAC>_<BSSID>_<mode_string>_<security_string>
  std::string GetStorageIdentifier() const override;

  // Validate |mode| against all valid and supported service modes.
  static bool IsValidMode(const std::string& mode);

  // Validate |method| against all valid and supported security methods.
  static bool IsValidSecurityMethod(const std::string& method);

  // Validate |security_class| against all valid and supported
  // security classes.
  static bool IsValidSecurityClass(const std::string& security_class);

  const std::string& mode() const { return mode_; }
  const std::string& key_management() const { return GetEAPKeyManagement(); }
  const std::vector<uint8_t>& ssid() const { return ssid_; }
  const std::string& bssid() const { return bssid_; }
  const std::vector<uint16_t>& frequency_list() const {
    return frequency_list_;
  }
  uint16_t physical_mode() const { return physical_mode_; }
  uint16_t frequency() const { return frequency_; }
  const std::string& security() const { return security_; }
  std::string security_class() const { return ComputeSecurityClass(security_); }

  TetheringState GetTethering() const override;

  // WiFi services can load from profile entries other than their current
  // storage identifier.  Override the methods from the parent Service
  // class which pertain to whether this service may be loaded from |storage|.
  std::string GetLoadableStorageIdentifier(
      const StoreInterface& storage) const override;
  bool IsLoadableFrom(const StoreInterface& storage) const override;

  // Override Storage methods from parent Service class.  We will call
  // the parent method.
  bool Load(const StoreInterface* storage) override;
  void MigrateDeprecatedStorage(StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;
  bool Unload() override;

  // Override SetState from parent Service class.  We will call the
  // parent method. We also reset roam_state_ here since a state change
  // means we are no longer roaming.
  void SetState(ConnectState state) override;

  // Updates |roam_state_|.
  void SetRoamState(RoamState state) override;
  RoamState roam_state() const { return roam_state_; }
  std::string GetRoamStateString() const;
  std::string CalculateRoamState(Error* error);

  void SetIsRekeyInProgress(bool is_rekey_in_progress);
  bool is_rekey_in_progress() const { return is_rekey_in_progress_; }
  base::Time last_rekey_time() const { return last_rekey_time_; }

  mockable bool HasEndpoints() const { return !endpoints_.empty(); }
  bool IsVisible() const override;
  bool IsSecurityMatch(const std::string& security) const;

  // Used by WiFi objects to indicate that the credentials for this network
  // have been called into question.  This method returns true if given this
  // suspicion, if it is probable that indeed these credentials are likely
  // to be incorrect.  Credentials that have never been used before are
  // considered suspect by default, while those which have been used
  // successfully in the past must have this method called a number of times
  // since the last time ResetSuspectedCredentialsFailures() was called.
  mockable bool AddSuspectedCredentialFailure();
  mockable void ResetSuspectedCredentialFailures();

  bool hidden_ssid() const { return hidden_ssid_; }

  void InitializeCustomMetrics() const;
  void SendPostReadyStateMetrics(
      int64_t time_resume_to_ready_milliseconds) const override;

  // Clear any cached credentials stored in wpa_supplicant related to |this|.
  // This will disconnect this service if it is currently connected.
  void ClearCachedCredentials();

  // Override from parent Service class to correctly update connectability
  // when the EAP credentials change for 802.1x networks.
  void OnEapCredentialsChanged(
      Service::UpdateCredentialsReason reason) override;

  // Called by WiFiService to reset state associated with prior success
  // of a connection with particular EAP credentials or a passphrase.
  void OnCredentialChange(Service::UpdateCredentialsReason reason);

  // Override from parent Service class to register hidden services once they
  // have been configured.
  void OnProfileConfigured() override;

  // Called by WiFiProvider to update the service credentials using a set of
  // Passpoint credentials identified during a match.
  void OnPasspointMatch(const PasspointCredentialsRefPtr& credentials,
                        uint64_t priority);

  // Called by WiFiProvider to reset the WiFi device reference on shutdown.
  virtual void ResetWiFi();

  // Called by WiFi to retrieve configuration parameters for wpa_supplicant.
  mockable KeyValueStore GetSupplicantConfigurationParameters() const;

  // "wpa", "rsn" and "psk" are equivalent from a configuration perspective.
  // This function maps them all into "psk".
  static std::string ComputeSecurityClass(const std::string& security);

  bool IsAutoConnectable(const char** reason) const override;

  std::string GetWiFiPassphrase(Error* error) override;

  // Get the Passpoint match type of "home", "roaming" or "unknown". This
  // returns empty if the service is not provisioned through Passpoint.
  std::string GetPasspointMatchType(Error* error);

  // Get current Passpoint's credentials FQDN, empty if the service is not
  // provisioned through Passpoint.
  std::string GetPasspointFQDN(Error* error);

  // Get current Passpoint's provisioning source, empty if the service is not
  // provisioned through Passpoint.
  std::string GetPasspointOrigin(Error* error);

  // Get current Passpoint's ID, empty if the service is not provisioned through
  // Passpoint.
  std::string GetPasspointID(Error* error);

  // Signal level in dBm.  If no current endpoint, returns
  // std::numeric_limits<int>::min().
  mockable int16_t SignalLevel() const;

  // UpdateMACAddress return type.
  struct UpdateMACAddressRet {
    std::string mac;
    bool update;
  };
  // Update MAC address when necessary e.g. when it needs to be re-rolled.
  // Returns the current MAC address (if randomized) and if it needs
  // to be updated in WPA Supplicant.
  UpdateMACAddressRet UpdateMACAddress();

  void EmitConnectionAttemptEvent() const;

  void set_expecting_disconnect(bool val) { expecting_disconnect_ = val; }
  bool expecting_disconnect() const { return expecting_disconnect_; }

  void set_bgscan_string(const std::string& val) { bgscan_string_ = val; }
  std::string bgscan_string() const { return bgscan_string_; }

  PasspointCredentialsRefPtr& parent_credentials() {
    return parent_credentials_;
  }
  void set_parent_credentials(const PasspointCredentialsRefPtr& credentials);
  uint64_t match_priority() const { return match_priority_; }
  void set_match_priority(uint64_t priority) { match_priority_ = priority; }

 protected:
  // Inherited from Service.
  void OnConnect(Error* error) override;
  void OnDisconnect(Error* error, const char* reason) override;
  bool IsDisconnectable(Error* error) const override;
  bool IsMeteredByServiceProperties() const override;

  void SetEAPKeyManagement(const std::string& key_management) override;

  bool CompareWithSameTechnology(const ServiceRefPtr& service,
                                 bool* decision) override;

 private:
  friend class WiFiServiceSecurityTest;
  friend class WiFiServiceTest;                     // SetPassphrase
  friend class WiFiServiceFuzzer;                   // SetPassphrase
  friend class WiFiServiceUpdateFromEndpointsTest;  // SignalToStrength
  FRIEND_TEST(MetricsTest, WiFiServicePostReady);
  FRIEND_TEST(MetricsTest, WiFiServicePostReadyEAP);
  FRIEND_TEST(WiFiMainTest, CurrentBSSChangedUpdateServiceEndpoint);
  FRIEND_TEST(WiFiServiceTest, AutoConnect);
  FRIEND_TEST(WiFiServiceTest, ClearWriteOnlyDerivedProperty);  // passphrase_
  FRIEND_TEST(WiFiServiceTest, ComputeCipher8021x);
  FRIEND_TEST(WiFiServiceTest, CompareWithSameTechnology);
  FRIEND_TEST(WiFiServiceTest, IsAutoConnectable);
  FRIEND_TEST(WiFiServiceTest, LoadHidden);
  FRIEND_TEST(WiFiServiceTest, SetPassphraseForNonPassphraseService);
  FRIEND_TEST(WiFiServiceTest, LoadAndUnloadPassphrase);
  FRIEND_TEST(WiFiServiceTest, LoadPassphraseClearCredentials);
  FRIEND_TEST(WiFiServiceTest, SetPassphraseResetHasEverConnected);
  FRIEND_TEST(WiFiServiceTest, SetPassphraseRemovesCachedCredentials);
  FRIEND_TEST(WiFiServiceTest, SignalToStrength);  // SignalToStrength
  FRIEND_TEST(WiFiServiceTest, SuspectedCredentialFailure);
  FRIEND_TEST(WiFiServiceTest, UpdateSecurity);  // SetEAPKeyManagement
  FRIEND_TEST(WiFiServiceTest, ChooseDevice);
  FRIEND_TEST(WiFiServiceTest, SetMACAddress);
  FRIEND_TEST(WiFiServiceTest, SetMACPolicy);
  FRIEND_TEST(WiFiServiceTest, UpdateMACAddressNonPersistentPolicy);
  FRIEND_TEST(WiFiServiceTest, UpdateMACAddressPersistentPolicy);
  FRIEND_TEST(WiFiServiceTest, UpdateMACAddressPolicySwitch);
  FRIEND_TEST(WiFiServiceTest, RandomizationNotSupported);
  FRIEND_TEST(WiFiServiceTest, RandomizationBlocklist);

  static const char kAnyDeviceAddress[];
  static const int kSuspectedCredentialFailureThreshold;

  static const char kStorageMACAddress[];
  static const char kStorageMACPolicy[];
  static const char kStoragePortalDetected[];
  static const char kStorageLeaseExpiry[];
  static const char kStorageDisconnectTime[];

  // Override the base clase implementation, because we need to allow
  // arguments that aren't base class methods.
  void HelpRegisterConstDerivedString(
      const std::string& name, std::string (WiFiService::*get)(Error* error));
  void HelpRegisterDerivedString(
      const std::string& name,
      std::string (WiFiService::*get)(Error* error),
      bool (WiFiService::*set)(const std::string& value, Error* error));
  void HelpRegisterWriteOnlyDerivedString(
      const std::string& name,
      bool (WiFiService::*set)(const std::string& value, Error* error),
      void (WiFiService::*clear)(Error* error),
      const std::string* default_value);
  void HelpRegisterDerivedUint16(const std::string& name,
                                 uint16_t (WiFiService::*get)(Error* error),
                                 bool (WiFiService::*set)(const uint16_t& value,
                                                          Error* error),
                                 void (WiFiService::*clear)(Error* error));

  RpcIdentifier GetDeviceRpcId(Error* error) const override;

  void ClearPassphrase(Error* error);

  // Check if an WPA3 service is connectable (e.g., underlying device does not
  // support WPA3-SAE?).
  bool IsWPA3Connectable() const;
  void UpdateConnectable();
  void UpdateFromEndpoints();
  void UpdateSecurity();

  static CryptoAlgorithm ComputeCipher8021x(
      const std::set<WiFiEndpointConstRefPtr>& endpoints);
  static void ValidateWEPPassphrase(const std::string& passphrase,
                                    Error* error);
  static void ValidateWPAPassphrase(const std::string& passphrase,
                                    Error* error);
  static void ParseWEPPassphrase(const std::string& passphrase,
                                 int* key_index,
                                 std::vector<uint8_t>* password_bytes,
                                 Error* error);
  static void ParseWPAPassphrase(const std::string& passphrase,
                                 std::vector<uint8_t>* passphrase_bytes,
                                 Error* error);
  static bool CheckWEPIsHex(const std::string& passphrase, Error* error);
  static bool CheckWEPKeyIndex(const std::string& passphrase, Error* error);
  static bool CheckWEPPrefix(const std::string& passphrase, Error* error);

  // Maps a signal value, in dBm, to a "strength" value, from
  // |Service::kStrengthMin| to |Service:kStrengthMax|.
  static uint8_t SignalToStrength(int16_t signal_dbm);

  // Create a default group name for this WiFi service.
  std::string GetDefaultStorageIdentifier() const;

  // Return the security of this service.  If visible, the security
  // reported from the representative endpoint is returned.  Otherwise
  // the configured security for the service is returned.
  std::string GetSecurity(Error* error);

  // Return the security class of this service.  If visible, the
  // security class of the representative endpoint is returned.
  // Otherwise the configured security class for the service is
  // returned.
  //
  // See also: ComputeSecurityClass.
  std::string GetSecurityClass(Error* error);

  // Profile data for a WPA/RSN service can be stored under a number of
  // different security types.  These functions create different storage
  // property lists based on whether they are saved with their generic
  // "psk" name or if they use the (legacy) specific "wpa" or "rsn" names.
  KeyValueStore GetStorageProperties() const;

  // Called from DBus and during Load to validate and apply a passphrase for
  // this service.  If the passphrase is successfully changed, UpdateConnectable
  // and OnCredentialChange are both called and the method returns true.  This
  // method will return false if the passphrase cannot be set.  If the
  // passphrase is already set to the value of |passphrase|, this method will
  // return false.  If it is due to an error, |error| will be populated with the
  // appropriate information.
  bool SetPassphrase(const std::string& passphrase, Error* error);

  // Called by SetPassphrase and LoadPassphrase to perform the check on a
  // passphrase change.  |passphrase| is the new passphrase to be used for the
  // service.  If the new passphrase is not different from the existing
  // passphrase, SetPassphraseInternal will return false.  |reason| signals how
  // the SetPassphraseInternal method was triggered.  If the method was called
  // from Load, the has_ever_connected flag will not be reset.  If the method
  // was called from SetPassphrase, has_ever_connected will be set to false.
  bool SetPassphraseInternal(const std::string& passphrase,
                             Service::UpdateCredentialsReason reason);

  // Select a WiFi device (e.g, for connecting a hidden service with no
  // endpoints).
  WiFiRefPtr ChooseDevice();

  // Return MAC address randomization policy setting.
  std::string GetMACPolicy(Error* error);

  // Set MAC address randomization policy.
  bool SetMACPolicy(const std::string& policy, Error* error);

  void SetWiFi(const WiFiRefPtr& new_wifi);

  Metrics::WiFiConnectionAttemptInfo ConnectionAttemptInfo() const;

  // Clock for time-related events.
  static std::unique_ptr<base::Clock> clock_;
  // Properties
  std::string passphrase_;
  bool need_passphrase_;
  // The current security mode. May be updated based on detected BSS.
  // TODO(b/157935328): consider factoring this out into a class, to hide some
  // of the overlap (but not identical) nature of Security and SecurityClass.
  std::string security_;
  // TODO(cmasone): see if the below can be pulled from the endpoint associated
  // with this service instead.
  const std::string mode_;
  bool hidden_ssid_;
  // Random MAC address policy.
  RandomizationPolicy random_mac_policy_ = RandomizationPolicy::Hardware;
  // MAC Address used when |random_mac_policy_| is set to |PersistentRandom|.
  // Empty otherwise.
  MACAddress mac_address_;
  // This tracks if particular service ever encountered Captive portal.
  // In order to improve user experience with MAC Address randomization,
  // we rotate (reshuffle) MAC Address periodically only if |security_|
  // is Open and only if user never encountered a captive portal.
  // Once this flag is set and saved, it never gets erased.
  bool was_portal_detected_ = false;
  // Lease time expiry and disconnect time, kept here just to know at
  // WiFiService layer whether we can regenerate MAC address before actually
  // connecting to the network.
  base::Time dhcp4_lease_expiry_;
  base::Time disconnect_time_;
  uint16_t frequency_;
  std::vector<uint16_t> frequency_list_;
  uint16_t physical_mode_;
  // The raw dBm signal strength from the associated endpoint.
  int16_t raw_signal_strength_;
  std::string hex_ssid_;
  std::string storage_identifier_;
  std::string bssid_;
  Stringmap vendor_information_;
  // The country code reported by the current endpoint.
  std::string country_code_;
  // If |security_| == kSecurity8021x, the crypto algorithm being used.
  // (Otherwise, crypto algorithm is implied by |security_|.)
  CryptoAlgorithm cipher_8021x_;

  // Track the number of consecutive times our current credentials have
  // been called into question.
  int suspected_credential_failures_;

  // Track whether or not we've warned about large signal values.
  // Used to avoid spamming the log.
  static bool logged_signal_warning;

  WiFiRefPtr wifi_;
  std::set<WiFiEndpointConstRefPtr> endpoints_;
  WiFiEndpointConstRefPtr current_endpoint_;
  const std::vector<uint8_t> ssid_;
  // Flag indicating if service disconnect is initiated by user for
  // connecting to other service.
  bool expecting_disconnect_;
  // The background scan configuration parameters.
  std::string bgscan_string_;
  std::unique_ptr<CertificateFile> certificate_file_;
  // Bare pointer is safe because WiFi service instances are owned by
  // the WiFiProvider and are guaranteed to be deallocated by the time
  // the WiFiProvider is.
  WiFiProvider* provider_;
  // The State property will remain Online during a roam or DHCP renewal to
  // preserve the service sort order. |roam_state_| is valid during this process
  // (while the Service is Online but reassociation is happening) only.
  RoamState roam_state_;
  // Indicates that the current BSS has attempted to "re-key". We optimistically
  // assume that this succeeds and don't perform any state transitions to avoid
  // disrupting connectivity.
  bool is_rekey_in_progress_;
  // Timestamp of the last attempted rising edge of the "re-key".
  base::Time last_rekey_time_;
  // Set of Passpoint credentials present when the service was populated by a
  // previous Passpoint match.
  PasspointCredentialsRefPtr parent_credentials_;
  // Passpoint network match score.
  uint64_t match_priority_;
};

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_SERVICE_H_
