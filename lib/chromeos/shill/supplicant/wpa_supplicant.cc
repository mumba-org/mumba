// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/wpa_supplicant.h"

#include <string>

#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

// static
const char WPASupplicant::kAuthModeWPAPSK[] = "WPA-PSK";
const char WPASupplicant::kAuthModeWPA2PSK[] = "WPA2-PSK";
const char WPASupplicant::kAuthModeBothPSK[] = "WPA2-PSK+WPA-PSK";
const char WPASupplicant::kAuthModeFTPSK[] = "FT-PSK";
const char WPASupplicant::kAuthModeEAPPrefix[] = "EAP-";
const char WPASupplicant::kAuthModeFTEAP[] = "FT-EAP";
const char WPASupplicant::kAuthModeInactive[] = "INACTIVE";
const char WPASupplicant::kAuthModeUnknown[] = "UNKNOWN";
const char WPASupplicant::kBSSPropertyAge[] = "Age";
const char WPASupplicant::kBSSPropertyBSSID[] = "BSSID";
const char WPASupplicant::kBSSPropertyFrequency[] = "Frequency";
const char WPASupplicant::kBSSPropertyIEs[] = "IEs";
const char WPASupplicant::kBSSPropertyMode[] = "Mode";
const char WPASupplicant::kBSSPropertyRates[] = "Rates";
const char WPASupplicant::kBSSPropertySSID[] = "SSID";
const char WPASupplicant::kBSSPropertySignal[] = "Signal";
// Location of the system root CA certificates.
const char WPASupplicant::kCaPath[] = "/etc/ssl/certs";
const char WPASupplicant::kCurrentBSSNull[] = "/";
const char WPASupplicant::kDBusAddr[] = "fi.w1.wpa_supplicant1";
const char WPASupplicant::kDBusPath[] = "/fi/w1/wpa_supplicant1";
const char WPASupplicant::kDebugLevelDebug[] = "debug";
const char WPASupplicant::kDebugLevelError[] = "error";
const char WPASupplicant::kDebugLevelExcessive[] = "excessive";
const char WPASupplicant::kDebugLevelInfo[] = "info";
const char WPASupplicant::kDebugLevelMsgDump[] = "msgdump";
const char WPASupplicant::kDebugLevelWarning[] = "warning";
const char WPASupplicant::kDriverNL80211[] = "nl80211";
const char WPASupplicant::kDriverWired[] = "wired";
const char WPASupplicant::kEAPParameterAlertUnknownCA[] = "unknown CA";
const char WPASupplicant::kEAPParameterFailure[] = "failure";
const char WPASupplicant::kEAPParameterSuccess[] = "success";
const char WPASupplicant::kEAPRequestedParameterPin[] = "PIN";
const char WPASupplicant::kEAPStatusAcceptProposedMethod[] =
    "accept proposed method";
const char WPASupplicant::kEAPStatusCompletion[] = "completion";
const char WPASupplicant::kEAPStatusLocalTLSAlert[] = "local TLS alert";
const char WPASupplicant::kEAPStatusParameterNeeded[] = "eap parameter needed";
const char WPASupplicant::kEAPStatusRemoteCertificateVerification[] =
    "remote certificate verification";
const char WPASupplicant::kEAPStatusRemoteTLSAlert[] = "remote TLS alert";
const char WPASupplicant::kEAPStatusStarted[] = "started";
const char WPASupplicant::kEnginePKCS11[] = "pkcs11";
const char WPASupplicant::kErrorNetworkUnknown[] =
    "fi.w1.wpa_supplicant1.NetworkUnknown";
const char WPASupplicant::kErrorInterfaceExists[] =
    "fi.w1.wpa_supplicant1.InterfaceExists";
const char WPASupplicant::kInterfacePropertyAssocStatusCode[] =
    "AssocStatusCode";
const char WPASupplicant::kInterfacePropertyAuthStatusCode[] = "AuthStatusCode";
const char WPASupplicant::kInterfacePropertyCapabilities[] = "Capabilities";
const char WPASupplicant::kInterfacePropertyConfigFile[] = "ConfigFile";
const char WPASupplicant::kInterfacePropertyCurrentBSS[] = "CurrentBSS";
const char WPASupplicant::kInterfacePropertyDepth[] = "depth";
const char WPASupplicant::kInterfacePropertyDisconnectReason[] =
    "DisconnectReason";
const char WPASupplicant::kInterfacePropertyRoamTime[] = "RoamTime";
const char WPASupplicant::kInterfacePropertyRoamComplete[] = "RoamComplete";
const char WPASupplicant::kInterfacePropertySessionLength[] = "SessionLength";
const char WPASupplicant::kInterfacePropertyCurrentAuthMode[] =
    "CurrentAuthMode";
const char WPASupplicant::kInterfacePropertyDriver[] = "Driver";
const char WPASupplicant::kInterfacePropertyName[] = "Ifname";
const char WPASupplicant::kInterfacePropertyState[] = "State";
const char WPASupplicant::kInterfacePropertySubject[] = "subject";
const char WPASupplicant::kInterfaceState4WayHandshake[] = "4way_handshake";
const char WPASupplicant::kInterfaceStateAssociated[] = "associated";
const char WPASupplicant::kInterfaceStateAssociating[] = "associating";
const char WPASupplicant::kInterfaceStateAuthenticating[] = "authenticating";
const char WPASupplicant::kInterfaceStateCompleted[] = "completed";
const char WPASupplicant::kInterfaceStateDisconnected[] = "disconnected";
const char WPASupplicant::kInterfaceStateGroupHandshake[] = "group_handshake";
const char WPASupplicant::kInterfaceStateInactive[] = "inactive";
const char WPASupplicant::kInterfaceStateScanning[] = "scanning";
const char WPASupplicant::kKeyManagementIeee8021X[] = "IEEE8021X";
const char WPASupplicant::kKeyManagementFTEAP[] = "FT-EAP";
const char WPASupplicant::kKeyManagementFTPSK[] = "FT-PSK";
const char WPASupplicant::kKeyManagementFTSAE[] = "FT-SAE";
const char WPASupplicant::kKeyManagementWPAEAP[] = "WPA-EAP";
const char WPASupplicant::kKeyManagementWPAEAPSHA256[] = "WPA-EAP-SHA256";
const char WPASupplicant::kKeyManagementWPAPSK[] = "WPA-PSK";
const char WPASupplicant::kKeyManagementSAE[] = "SAE";
const char WPASupplicant::kKeyManagementMethodPrefixEAP[] = "wpa-eap";
const char WPASupplicant::kKeyManagementMethodSuffixEAP[] = "-eap";
const char WPASupplicant::kKeyManagementMethodSuffixPSK[] = "-psk";
const char WPASupplicant::kKeyManagementMethodSAE[] = "sae";
const char WPASupplicant::kKeyManagementNone[] = "NONE";
const char WPASupplicant::kNetworkBgscanMethodLearn[] = "learn";
// None is not a real method name, but we interpret 'none' as a request that
// no background scan parameter should be supplied to wpa_supplicant.
const char WPASupplicant::kNetworkBgscanMethodNone[] = "none";
const char WPASupplicant::kNetworkBgscanMethodSimple[] = "simple";
const char WPASupplicant::kNetworkModeInfrastructure[] = "infrastructure";
const char WPASupplicant::kNetworkModeAdHoc[] = "ad-hoc";
const char WPASupplicant::kNetworkModeAccessPoint[] = "ap";
const char WPASupplicant::kNetworkModeMesh[] = "mesh";
const char WPASupplicant::kNetworkModeP2P[] = "p2p";
const char WPASupplicant::kNetworkPropertyBgscan[] = "bgscan";
const char WPASupplicant::kNetworkPropertyCaPath[] = "ca_path";
const char WPASupplicant::kNetworkPropertyDisableVHT[] = "disable_vht";
const char WPASupplicant::kNetworkPropertyEapIdentity[] = "identity";
const char WPASupplicant::kNetworkPropertyEapKeyManagement[] = "key_mgmt";
const char WPASupplicant::kNetworkPropertyEapEap[] = "eap";
const char WPASupplicant::kNetworkPropertyEapOuterEap[] = "phase1";
const char WPASupplicant::kNetworkPropertyEapInnerEap[] = "phase2";
const char WPASupplicant::kNetworkPropertyEapAnonymousIdentity[] =
    "anonymous_identity";
const char WPASupplicant::kNetworkPropertyEapProactiveKeyCaching[] =
    "proactive_key_caching";
const char WPASupplicant::kNetworkPropertyEapCaCert[] = "ca_cert";
const char WPASupplicant::kNetworkPropertyEapCaPassword[] = "password";
const char WPASupplicant::kNetworkPropertyEapCertId[] = "cert_id";
const char WPASupplicant::kNetworkPropertyEapKeyId[] = "key_id";
const char WPASupplicant::kNetworkPropertyEapCaCertId[] = "ca_cert_id";
const char WPASupplicant::kNetworkPropertyEapPin[] = "pin";
const char WPASupplicant::kNetworkPropertyEapSubjectMatch[] = "subject_match";
const char WPASupplicant::kNetworkPropertyEapSubjectAlternativeNameMatch[] =
    "altsubject_match";
const char WPASupplicant::kNetworkPropertyEapDomainSuffixMatch[] =
    "domain_suffix_match";
const char WPASupplicant::kNetworkPropertyEapolFlags[] = "eapol_flags";
const char WPASupplicant::kNetworkPropertyEngine[] = "engine";
const char WPASupplicant::kNetworkPropertyEngineId[] = "engine_id";
const char WPASupplicant::kNetworkPropertyFrequency[] = "frequency";
const char WPASupplicant::kNetworkPropertyIeee80211w[] = "ieee80211w";
const char WPASupplicant::kNetworkPropertyMACAddrPolicy[] = "mac_addr";
const char WPASupplicant::kNetworkPropertyMACAddrValue[] = "mac_value";
const char WPASupplicant::kNetworkPropertyMode[] = "mode";
const char WPASupplicant::kNetworkPropertyScanSSID[] = "scan_ssid";
const char WPASupplicant::kNetworkPropertySSID[] = "ssid";
const char WPASupplicant::kPropertyAuthAlg[] = "auth_alg";
const char WPASupplicant::kPropertyPreSharedKey[] = "psk";
const char WPASupplicant::kPropertyPrivacy[] = "Privacy";
const char WPASupplicant::kPropertyRSN[] = "RSN";
const char WPASupplicant::kPropertyScanAllowRoam[] = "AllowRoam";
const char WPASupplicant::kPropertyScanSSIDs[] = "SSIDs";
const char WPASupplicant::kPropertyScanType[] = "Type";
const char WPASupplicant::kPropertySecurityProtocol[] = "proto";
const char WPASupplicant::kPropertyWEPKey[] = "wep_key";
const char WPASupplicant::kPropertyWEPTxKeyIndex[] = "wep_tx_keyidx";
const char WPASupplicant::kPropertyWPA[] = "WPA";
const char WPASupplicant::kScanTypeActive[] = "active";
const char WPASupplicant::kSecurityAuthAlg[] = "OPEN SHARED";
const char WPASupplicant::kSecurityMethodPropertyKeyManagement[] = "KeyMgmt";
const char WPASupplicant::kSecurityModeRSN[] = "RSN";
const char WPASupplicant::kSecurityModeWPA[] = "WPA";

const char WPASupplicant::kCredentialsPropertyDomain[] = "domain";
const char WPASupplicant::kCredentialsPropertyPassword[] = "password";
const char WPASupplicant::kCredentialsPropertyRealm[] = "realm";
const char WPASupplicant::kCredentialsPropertyRoamingConsortium[] =
    "roaming_consortium";
const char WPASupplicant::kCredentialsPropertyRequiredRoamingConsortium[] =
    "required_roaming_consortium";
const char WPASupplicant::kCredentialsPropertyRoamingConsortiums[] =
    "roaming_consortiums";
const char WPASupplicant::kCredentialsPropertyUsername[] = "username";
const char WPASupplicant::kCredentialsMatchType[] = "type";
const char WPASupplicant::kCredentialsMatchTypeHome[] = "home";
const char WPASupplicant::kCredentialsMatchTypeRoaming[] = "roaming";
const char WPASupplicant::kCredentialsMatchTypeUnknown[] = "unknown";

const char WPASupplicant::kInterfaceCapabilityMaxScanSSID[] = "MaxScanSSID";

const char WPASupplicant::kFlagDisableEapTLS1p1[] = "tls_disable_tlsv1_1=1";
const char WPASupplicant::kFlagDisableEapTLS1p2[] = "tls_disable_tlsv1_2=1";
const char WPASupplicant::kFlagInnerEapAuthMSCHAPV2[] = "auth=MSCHAPV2";
const char WPASupplicant::kFlagInnerEapNoMSCHAPV2Retry[] = "mschapv2_retry=0";

const uint32_t WPASupplicant::kDefaultEngine = 1;
const uint32_t WPASupplicant::kNetworkIeee80211wDisabled = 0;
const uint32_t WPASupplicant::kNetworkIeee80211wEnabled = 1;
const uint32_t WPASupplicant::kNetworkIeee80211wRequired = 2;
const uint32_t WPASupplicant::kNetworkModeInfrastructureInt = 0;
const uint32_t WPASupplicant::kNetworkModeAdHocInt = 1;
const uint32_t WPASupplicant::kNetworkModeAccessPointInt = 2;
const uint32_t WPASupplicant::kDefaultMaxSSIDsPerScan = 4;
// A maximum value to which MaxScanSSID capability should be clipped - the value
// is aligned with limit in WPA Supplicant (see WPAS_MAX_SCAN_SSIDS there).
const uint32_t WPASupplicant::kMaxMaxSSIDsPerScan = 16;

const uint32_t WPASupplicant::kProactiveKeyCachingDisabled = 0;
const uint32_t WPASupplicant::kProactiveKeyCachingEnabled = 1;

const char WPASupplicant::kSupplicantConfPath[] =
    SHIMDIR "/wpa_supplicant.conf";

const int32_t WPASupplicant::kMACAddrPolicyHardware = 0;
const int32_t WPASupplicant::kMACAddrPolicyFullRandom = 1;
const int32_t WPASupplicant::kMACAddrPolicyOUIRandom = 2;
const int32_t WPASupplicant::kMACAddrPolicyPersistentRandom = 3;

// static
bool WPASupplicant::ExtractRemoteCertification(const KeyValueStore& properties,
                                               std::string* subject,
                                               uint32_t* depth) {
  if (!properties.Contains<uint32_t>(WPASupplicant::kInterfacePropertyDepth)) {
    LOG(ERROR) << __func__ << " no depth parameter.";
    return false;
  }
  if (!properties.Contains<std::string>(
          WPASupplicant::kInterfacePropertySubject)) {
    LOG(ERROR) << __func__ << " no subject parameter.";
    return false;
  }

  *depth = properties.Get<uint32_t>(WPASupplicant::kInterfacePropertyDepth);
  *subject =
      properties.Get<std::string>(WPASupplicant::kInterfacePropertySubject);
  return true;
}

}  // namespace shill
