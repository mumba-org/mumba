// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_METRICS_H_
#define SHILL_METRICS_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <metrics/metrics_library.h>
#include <metrics/timer.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "shill/default_service_observer.h"
#include "shill/error.h"
#include "shill/portal_detector.h"
#include "shill/power_manager.h"
#include "shill/refptr_types.h"
#include "shill/service.h"

#if !defined(DISABLE_WIFI)
#include "shill/net/ieee80211.h"
#include "shill/wifi/wake_on_wifi.h"
#endif  // DISABLE_WIFI

namespace shill {

class WiFiEndPoint;

class Metrics : public DefaultServiceObserver {
 public:
  enum WiFiChannel {
    kWiFiChannelUndef = 0,
    kWiFiChannel2412 = 1,
    kWiFiChannelMin24 = kWiFiChannel2412,
    kWiFiChannel2417 = 2,
    kWiFiChannel2422 = 3,
    kWiFiChannel2427 = 4,
    kWiFiChannel2432 = 5,
    kWiFiChannel2437 = 6,
    kWiFiChannel2442 = 7,
    kWiFiChannel2447 = 8,
    kWiFiChannel2452 = 9,
    kWiFiChannel2457 = 10,
    kWiFiChannel2462 = 11,
    kWiFiChannel2467 = 12,
    kWiFiChannel2472 = 13,
    kWiFiChannel2484 = 14,
    kWiFiChannelMax24 = kWiFiChannel2484,

    kWiFiChannel5180 = 15,
    kWiFiChannelMin5 = kWiFiChannel5180,
    kWiFiChannel5200 = 16,
    kWiFiChannel5220 = 17,
    kWiFiChannel5240 = 18,
    kWiFiChannel5260 = 19,
    kWiFiChannel5280 = 20,
    kWiFiChannel5300 = 21,
    kWiFiChannel5320 = 22,

    kWiFiChannel5500 = 23,
    kWiFiChannel5520 = 24,
    kWiFiChannel5540 = 25,
    kWiFiChannel5560 = 26,
    kWiFiChannel5580 = 27,
    kWiFiChannel5600 = 28,
    kWiFiChannel5620 = 29,
    kWiFiChannel5640 = 30,
    kWiFiChannel5660 = 31,
    kWiFiChannel5680 = 32,
    kWiFiChannel5700 = 33,

    kWiFiChannel5745 = 34,
    kWiFiChannel5765 = 35,
    kWiFiChannel5785 = 36,
    kWiFiChannel5805 = 37,
    kWiFiChannel5825 = 38,

    kWiFiChannel5170 = 39,
    kWiFiChannel5190 = 40,
    kWiFiChannel5210 = 41,
    kWiFiChannel5230 = 42,
    kWiFiChannelMax5 = kWiFiChannel5230,

    kWiFiChannel5955 = 43,
    kWiFiChannelMin6 = kWiFiChannel5955,
    kWiFiChannel5975 = 44,
    kWiFiChannel5995 = 45,
    kWiFiChannel6015 = 46,
    kWiFiChannel6035 = 47,
    kWiFiChannel6055 = 48,
    kWiFiChannel6075 = 49,
    kWiFiChannel6095 = 50,
    kWiFiChannel6115 = 51,
    kWiFiChannel6135 = 52,
    kWiFiChannel6155 = 53,
    kWiFiChannel6175 = 54,
    kWiFiChannel6195 = 55,
    kWiFiChannel6215 = 56,
    kWiFiChannel6235 = 57,
    kWiFiChannel6255 = 58,
    kWiFiChannel6275 = 59,
    kWiFiChannel6295 = 60,
    kWiFiChannel6315 = 61,
    kWiFiChannel6335 = 62,
    kWiFiChannel6355 = 63,
    kWiFiChannel6375 = 64,
    kWiFiChannel6395 = 65,
    kWiFiChannel6415 = 66,
    kWiFiChannel6435 = 67,
    kWiFiChannel6455 = 68,
    kWiFiChannel6475 = 69,
    kWiFiChannel6495 = 70,
    kWiFiChannel6515 = 71,
    kWiFiChannel6535 = 72,
    kWiFiChannel6555 = 73,
    kWiFiChannel6575 = 74,
    kWiFiChannel6595 = 75,
    kWiFiChannel6615 = 76,
    kWiFiChannel6635 = 77,
    kWiFiChannel6655 = 78,
    kWiFiChannel6675 = 79,
    kWiFiChannel6695 = 80,
    kWiFiChannel6715 = 81,
    kWiFiChannel6735 = 82,
    kWiFiChannel6755 = 83,
    kWiFiChannel6775 = 84,
    kWiFiChannel6795 = 85,
    kWiFiChannel6815 = 86,
    kWiFiChannel6835 = 87,
    kWiFiChannel6855 = 88,
    kWiFiChannel6875 = 89,
    kWiFiChannel6895 = 90,
    kWiFiChannel6915 = 91,
    kWiFiChannel6935 = 92,
    kWiFiChannel6955 = 93,
    kWiFiChannel6975 = 94,
    kWiFiChannel6995 = 95,
    kWiFiChannel7015 = 96,
    kWiFiChannel7035 = 97,
    kWiFiChannel7055 = 98,
    kWiFiChannel7075 = 99,
    kWiFiChannel7095 = 100,
    kWiFiChannel7115 = 101,
    kWiFiChannelMax6 = kWiFiChannel7115,

    /* NB: ignore old 11b bands 2312..2372 and 2512..2532 */
    /* NB: ignore regulated bands 4920..4980 and 5020..5160 */
    kWiFiChannelMax
  };

  enum WiFiFrequencyRange {
    kWiFiFrequencyRangeUndef = 0,
    kWiFiFrequencyRange24 = 1,
    kWiFiFrequencyRange5 = 2,
    kWiFiFrequencyRange6 = 3,

    kWiFiFrequencyRangeMax
  };

  enum WiFiNetworkPhyMode {
    kWiFiNetworkPhyModeUndef = 0,    // Unknown/undefined
    kWiFiNetworkPhyMode11a = 1,      // 802.11a
    kWiFiNetworkPhyMode11b = 2,      // 802.11b
    kWiFiNetworkPhyMode11g = 3,      // 802.11g
    kWiFiNetworkPhyMode11n = 4,      // 802.11n
    kWiFiNetworkPhyModeHalf = 5,     // PSB Half-width
    kWiFiNetworkPhyModeQuarter = 6,  // PSB Quarter-width
    kWiFiNetworkPhyMode11ac = 7,     // 802.11ac
    kWiFiNetworkPhyMode11ax = 8,     // 802.11ax

    kWiFiNetworkPhyModeMax
  };

  enum EapOuterProtocol {
    kEapOuterProtocolUnknown = 0,
    kEapOuterProtocolLeap = 1,
    kEapOuterProtocolPeap = 2,
    kEapOuterProtocolTls = 3,
    kEapOuterProtocolTtls = 4,

    kEapOuterProtocolMax
  };

  enum EapInnerProtocol {
    kEapInnerProtocolUnknown = 0,
    kEapInnerProtocolNone = 1,
    kEapInnerProtocolPeapMd5 = 2,
    kEapInnerProtocolPeapMschapv2 = 3,
    kEapInnerProtocolTtlsEapMd5 = 4,
    kEapInnerProtocolTtlsEapMschapv2 = 5,
    kEapInnerProtocolTtlsMschapv2 = 6,
    kEapInnerProtocolTtlsMschap = 7,
    kEapInnerProtocolTtlsPap = 8,
    kEapInnerProtocolTtlsChap = 9,

    kEapInnerProtocolMax
  };

  enum WiFiSecurity {
    kWiFiSecurityUnknown = 0,
    kWiFiSecurityNone = 1,
    kWiFiSecurityWep = 2,
    kWiFiSecurityWpa = 3,
    kWiFiSecurityRsn = 4,
    kWiFiSecurity8021x = 5,
    kWiFiSecurityPsk = 6,
    kWiFiSecurityWpa3 = 7,

    kWiFiSecurityMax
  };

  enum PortalResult {
    kPortalResultSuccess = 0,
    kPortalResultDNSFailure = 1,
    kPortalResultDNSTimeout = 2,
    kPortalResultConnectionFailure = 3,
    kPortalResultConnectionTimeout = 4,
    kPortalResultHTTPFailure = 5,
    kPortalResultHTTPTimeout = 6,
    kPortalResultContentFailure = 7,
    kPortalResultContentTimeout = 8,
    kPortalResultUnknown = 9,
    kPortalResultContentRedirect = 10,

    kPortalResultMax
  };

  enum NeighborLinkMonitorFailure {
    kNeighborLinkMonitorFailureUnknown = 0,
    kNeighborIPv4GatewayFailure = 1,
    kNeighborIPv4DNSServerFailure = 2,
    kNeighborIPv4GatewayAndDNSServerFailure = 3,
    kNeighborIPv6GatewayFailure = 4,
    kNeighborIPv6DNSServerFailure = 5,
    kNeighborIPv6GatewayAndDNSServerFailure = 6,

    kNeighborLinkMonitorFailureMax
  };

  enum WiFiApChannelSwitch {
    kWiFiApChannelSwitchUndef = 0,
    kWiFiApChannelSwitch24To24 = 1,
    kWiFiApChannelSwitch24To5 = 2,
    kWiFiApChannelSwitch5To24 = 3,
    kWiFiApChannelSwitch5To5 = 4,

    kWiFiApChannelSwitchMax
  };

  enum WiFiAp80211rSupport {
    kWiFiAp80211rNone = 0,
    kWiFiAp80211rOTA = 1,
    kWiFiAp80211rOTDS = 2,

    kWiFiAp80211rMax
  };

  enum WiFiRoamComplete {
    kWiFiRoamSuccess = 0,
    kWiFiRoamFailure = 1,

    kWiFiRoamCompleteMax
  };

  enum WiFiCQMReason {
    kWiFiCQMPacketLoss = 0,
    kWiFiCQMBeaconLoss = 1,

    kWiFiCQMMax
  };

  enum WiFiReasonType {
    kReasonCodeTypeByAp,
    kReasonCodeTypeByClient,
    kReasonCodeTypeByUser,
    kReasonCodeTypeConsideredDead,
    kReasonCodeTypeMax
  };

  enum WiFiDisconnectByWhom { kDisconnectedByAp, kDisconnectedNotByAp };

  enum WiFiScanResult {
    kScanResultProgressiveConnected,
    kScanResultProgressiveErrorAndFullFoundNothing,
    kScanResultProgressiveErrorButFullConnected,
    kScanResultProgressiveAndFullFoundNothing,
    kScanResultProgressiveAndFullConnected,
    kScanResultFullScanFoundNothing,
    kScanResultFullScanConnected,
    kScanResultInternalError,
    kScanResultMax
  };

  enum SuspendActionResult {
    kSuspendActionResultSuccess,
    kSuspendActionResultFailure,
    kSuspendActionResultMax
  };

  enum Cellular3GPPRegistrationDelayedDrop {
    kCellular3GPPRegistrationDelayedDropPosted = 0,
    kCellular3GPPRegistrationDelayedDropCanceled = 1,
    kCellular3GPPRegistrationDelayedDropMax
  };

  enum CellularApnSource {
    kCellularApnSourceMoDb = 0,
    kCellularApnSourceUi = 1,
    kCellularApnSourceModem = 2,
    kCellularApnSourceMax
  };

  enum CellularDropTechnology {
    kCellularDropTechnology1Xrtt = 0,
    kCellularDropTechnologyEdge = 1,
    kCellularDropTechnologyEvdo = 2,
    kCellularDropTechnologyGprs = 3,
    kCellularDropTechnologyGsm = 4,
    kCellularDropTechnologyHspa = 5,
    kCellularDropTechnologyHspaPlus = 6,
    kCellularDropTechnologyLte = 7,
    kCellularDropTechnologyUmts = 8,
    kCellularDropTechnologyUnknown = 9,
    kCellularDropTechnology5gNr = 10,
    kCellularDropTechnologyMax
  };

  // These values are persisted to logs for
  // Network.Shill.Cellular.ConnectResult. CellularConnectResult entries should
  // not be renumbered and numeric values should never be reused.
  enum class CellularConnectResult {
    kCellularConnectResultSuccess = 0,
    kCellularConnectResultUnknown = 1,
    kCellularConnectResultWrongState = 2,
    kCellularConnectResultOperationFailed = 3,
    kCellularConnectResultAlreadyConnected = 4,
    kCellularConnectResultNotRegistered = 5,
    kCellularConnectResultNotOnHomeNetwork = 6,
    kCellularConnectResultIncorrectPin = 7,
    kCellularConnectResultPinRequired = 8,
    kCellularConnectResultPinBlocked = 9,
    kCellularConnectResultInvalidApn = 10,
    kCellularConnectResultMax
  };

  enum CellularRoamingState {
    kCellularRoamingStateUnknown = 0,
    kCellularRoamingStateHome = 1,
    kCellularRoamingStateRoaming = 2,
    kCellularRoamingStateMax
  };

  enum CellularOutOfCreditsReason {
    kCellularOutOfCreditsReasonConnectDisconnectLoop = 0,
    kCellularOutOfCreditsReasonTxCongested = 1,
    kCellularOutOfCreditsReasonElongatedTimeWait = 2,
    kCellularOutOfCreditsReasonMax
  };

  enum CorruptedProfile { kCorruptedProfile = 1, kCorruptedProfileMax };

  enum ConnectionDiagnosticsIssue {
    kConnectionDiagnosticsIssueIPCollision = 0,
    kConnectionDiagnosticsIssueRouting = 1,
    kConnectionDiagnosticsIssueHTTPBrokenPortal = 2,
    kConnectionDiagnosticsIssueDNSServerMisconfig = 3,
    kConnectionDiagnosticsIssueDNSServerNoResponse = 4,
    kConnectionDiagnosticsIssueNoDNSServersConfigured = 5,
    kConnectionDiagnosticsIssueDNSServersInvalid = 6,
    kConnectionDiagnosticsIssueNone = 7,
    kConnectionDiagnosticsIssueCaptivePortal = 8,
    kConnectionDiagnosticsIssueGatewayUpstream = 9,
    kConnectionDiagnosticsIssueGatewayNotResponding = 10,
    kConnectionDiagnosticsIssueServerNotResponding = 11,
    kConnectionDiagnosticsIssueGatewayArpFailed = 12,
    kConnectionDiagnosticsIssueServerArpFailed = 13,
    kConnectionDiagnosticsIssueInternalError = 14,
    kConnectionDiagnosticsIssueGatewayNoNeighborEntry = 15,
    kConnectionDiagnosticsIssueServerNoNeighborEntry = 16,
    kConnectionDiagnosticsIssueGatewayNeighborEntryNotConnected = 17,
    kConnectionDiagnosticsIssueServerNeighborEntryNotConnected = 18,
    kConnectionDiagnosticsIssuePlaceholder1 = 19,
    kConnectionDiagnosticsIssuePlaceholder2 = 20,
    kConnectionDiagnosticsIssuePlaceholder3 = 21,
    kConnectionDiagnosticsIssuePlaceholder4 = 22,
    kConnectionDiagnosticsIssueMax
  };

  enum PortalDetectionMultiProbeResult {
    kPortalDetectionMultiProbeResultUndefined = 0,
    kPortalDetectionMultiProbeResultHTTPSBlockedHTTPBlocked = 1,
    kPortalDetectionMultiProbeResultHTTPSBlockedHTTPRedirected = 2,
    kPortalDetectionMultiProbeResultHTTPSBlockedHTTPUnblocked = 3,
    kPortalDetectionMultiProbeResultHTTPSUnblockedHTTPBlocked = 4,
    kPortalDetectionMultiProbeResultHTTPSUnblockedHTTPRedirected = 5,
    kPortalDetectionMultiProbeResultHTTPSUnblockedHTTPUnblocked = 6,
    kPortalDetectionMultiProbeResultMax
  };

  enum VpnDriver {
    kVpnDriverOpenVpn = 0,
    kVpnDriverL2tpIpsec = 1,
    kVpnDriverThirdParty = 2,
    kVpnDriverArc = 3,
    // 4 is occupied by PPTP in chrome.
    kVpnDriverWireGuard = 5,
    kVpnDriverIKEv2 = 6,
    kVpnDriverMax
  };

  enum VpnRemoteAuthenticationType {
    kVpnRemoteAuthenticationTypeOpenVpnDefault = 0,
    kVpnRemoteAuthenticationTypeOpenVpnCertificate = 1,
    kVpnRemoteAuthenticationTypeL2tpIpsecDefault = 2,
    kVpnRemoteAuthenticationTypeL2tpIpsecCertificate = 3,
    kVpnRemoteAuthenticationTypeL2tpIpsecPsk = 4,
    kVpnRemoteAuthenticationTypeMax
  };

  enum VpnUserAuthenticationType {
    kVpnUserAuthenticationTypeOpenVpnNone = 0,
    kVpnUserAuthenticationTypeOpenVpnCertificate = 1,
    kVpnUserAuthenticationTypeOpenVpnUsernamePassword = 2,
    kVpnUserAuthenticationTypeOpenVpnUsernamePasswordOtp = 3,
    kVpnUserAuthenticationTypeOpenVpnUsernameToken = 7,
    kVpnUserAuthenticationTypeL2tpIpsecNone = 4,
    kVpnUserAuthenticationTypeL2tpIpsecCertificate = 5,
    kVpnUserAuthenticationTypeL2tpIpsecUsernamePassword = 6,
    kVpnUserAuthenticationTypeMax
  };

  enum VpnIpsecAuthenticationType {
    kVpnIpsecAuthenticationTypeUnknown = 0,
    kVpnIpsecAuthenticationTypePsk = 1,
    kVpnIpsecAuthenticationTypeEap = 2,
    kVpnIpsecAuthenticationTypeCertificate = 3,
    kVpnIpsecAuthenticationTypeMax
  };

  enum VpnL2tpIpsecTunnelGroupUsage {
    kVpnL2tpIpsecTunnelGroupUsageNo = 0,
    kVpnL2tpIpsecTunnelGroupUsageYes = 1,
    kVpnL2tpIpsecTunnelGroupUsageMax
  };

  // This enum contains the encryption algorithms we are using for IPsec now,
  // but not the complete list of algorithms which are supported by strongswan.
  // It is the same for the following enums for integrity algorithms and DH
  // groups.
  enum VpnIpsecEncryptionAlgorithm {
    kVpnIpsecEncryptionAlgorithmUnknown = 0,

    kVpnIpsecEncryptionAlgorithm_AES_CBC_128 = 1,
    kVpnIpsecEncryptionAlgorithm_AES_CBC_192 = 2,
    kVpnIpsecEncryptionAlgorithm_AES_CBC_256 = 3,
    kVpnIpsecEncryptionAlgorithm_CAMELLIA_CBC_128 = 4,
    kVpnIpsecEncryptionAlgorithm_CAMELLIA_CBC_192 = 5,
    kVpnIpsecEncryptionAlgorithm_CAMELLIA_CBC_256 = 6,
    kVpnIpsecEncryptionAlgorithm_3DES_CBC = 7,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_16_128 = 8,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_16_192 = 9,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_16_256 = 10,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_12_128 = 11,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_12_192 = 12,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_12_256 = 13,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_8_128 = 14,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_8_192 = 15,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_8_256 = 16,

    kVpnIpsecEncryptionAlgorithmMax,
  };

  enum VpnIpsecIntegrityAlgorithm {
    kVpnIpsecIntegrityAlgorithmUnknown = 0,

    kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128 = 1,
    kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_384_192 = 2,
    kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_512_256 = 3,
    kVpnIpsecIntegrityAlgorithm_HMAC_SHA1_96 = 4,
    kVpnIpsecIntegrityAlgorithm_AES_XCBC_96 = 5,
    kVpnIpsecIntegrityAlgorithm_AES_CMAC_96 = 6,

    kVpnIpsecIntegrityAlgorithmMax,
  };

  enum VpnIpsecDHGroup {
    kVpnIpsecDHGroupUnknown = 0,

    kVpnIpsecDHGroup_ECP_256 = 1,
    kVpnIpsecDHGroup_ECP_384 = 2,
    kVpnIpsecDHGroup_ECP_521 = 3,
    kVpnIpsecDHGroup_ECP_256_BP = 4,
    kVpnIpsecDHGroup_ECP_384_BP = 5,
    kVpnIpsecDHGroup_ECP_512_BP = 6,
    kVpnIpsecDHGroup_CURVE_25519 = 7,
    kVpnIpsecDHGroup_CURVE_448 = 8,
    kVpnIpsecDHGroup_MODP_1024 = 9,
    kVpnIpsecDHGroup_MODP_1536 = 10,
    kVpnIpsecDHGroup_MODP_2048 = 11,
    kVpnIpsecDHGroup_MODP_3072 = 12,
    kVpnIpsecDHGroup_MODP_4096 = 13,
    kVpnIpsecDHGroup_MODP_6144 = 14,
    kVpnIpsecDHGroup_MODP_8192 = 15,

    kVpnIpsecDHGroupMax,
  };

  enum VpnOpenVPNCipher {
    kVpnOpenVPNCipherUnknown = 0,
    kVpnOpenVPNCipher_BF_CBC = 1,
    kVpnOpenVPNCipher_AES_256_GCM = 2,
    kVpnOpenVPNCipher_AES_128_GCM = 3,
    kVpnOpenVPNCipherMax
  };

  enum VpnWireGuardKeyPairSource {
    kVpnWireguardKeyPairSourceUnknown = 0,
    kVpnWireGuardKeyPairSourceUserInput = 1,
    kVpnWireGuardKeyPairSourceSoftwareGenerated = 2,
    kVpnWireGuardKeyPairSourceMax
  };

  enum VpnWireGuardAllowedIPsType {
    kVpnWireGuardAllowedIPsTypeHasDefaultRoute = 0,
    kVpnWireGuardAllowedIPsTypeNoDefaultRoute = 1,
    kVpnWireGuardAllowedIPsTypeMax
  };

  // Result of a connection initiated by Service::UserInitiatedConnect.
  enum UserInitiatedConnectionResult {
    kUserInitiatedConnectionResultSuccess = 0,
    kUserInitiatedConnectionResultFailure = 1,
    kUserInitiatedConnectionResultAborted = 2,
    kUserInitiatedConnectionResultMax
  };

  // Device's connection status.
  enum ConnectionStatus {
    kConnectionStatusOffline = 0,
    kConnectionStatusConnected = 1,
    kConnectionStatusOnline = 2,
    kConnectionStatusMax
  };

  // Reason when a connection initiated by Service::UserInitiatedConnect fails.
  enum UserInitiatedConnectionFailureReason {
    kUserInitiatedConnectionFailureReasonBadPassphrase = 1,
    kUserInitiatedConnectionFailureReasonBadWEPKey = 2,
    kUserInitiatedConnectionFailureReasonConnect = 3,
    kUserInitiatedConnectionFailureReasonDHCP = 4,
    kUserInitiatedConnectionFailureReasonDNSLookup = 5,
    kUserInitiatedConnectionFailureReasonEAPAuthentication = 6,
    kUserInitiatedConnectionFailureReasonEAPLocalTLS = 7,
    kUserInitiatedConnectionFailureReasonEAPRemoteTLS = 8,
    kUserInitiatedConnectionFailureReasonOutOfRange = 9,
    kUserInitiatedConnectionFailureReasonPinMissing = 10,
    kUserInitiatedConnectionFailureReasonUnknown = 11,
    kUserInitiatedConnectionFailureReasonNone = 12,
    kUserInitiatedConnectionFailureReasonNotAssociated = 13,
    kUserInitiatedConnectionFailureReasonNotAuthenticated = 14,
    kUserInitiatedConnectionFailureReasonTooManySTAs = 15,
    kUserInitiatedConnectionFailureReasonMax
  };

  enum NetworkConnectionIPType {
    kNetworkConnectionIPTypeIPv4 = 0,
    kNetworkConnectionIPTypeIPv6 = 1,
    kNetworkConnectionIPTypeMax
  };

  enum IPv6ConnectivityStatus {
    kIPv6ConnectivityStatusNo = 0,
    kIPv6ConnectivityStatusYes = 1,
    kIPv6ConnectivityStatusMax
  };

  enum DevicePresenceStatus {
    kDevicePresenceStatusNo = 0,
    kDevicePresenceStatusYes = 1,
    kDevicePresenceStatusMax
  };

  enum DeviceTechnologyType {
    kDeviceTechnologyTypeUnknown = 0,
    kDeviceTechnologyTypeEthernet = 1,
    kDeviceTechnologyTypeWifi = 2,
    // deprecated: kDeviceTechnologyTypeWimax = 3,
    kDeviceTechnologyTypeCellular = 4,
    kDeviceTechnologyTypeMax
  };

  // These correspond to entries in Chrome's tools/metrics/histograms/enums.xml.
  // Please do not remove entries (append 'Deprecated' instead), and update the
  // enums.xml file when entries are added.
  enum NetworkServiceError {
    kNetworkServiceErrorNone = 0,
    kNetworkServiceErrorAAA = 1,
    kNetworkServiceErrorActivation = 2,
    kNetworkServiceErrorBadPassphrase = 3,
    kNetworkServiceErrorBadWEPKey = 4,
    kNetworkServiceErrorConnect = 5,
    kNetworkServiceErrorDHCP = 6,
    kNetworkServiceErrorDNSLookup = 7,
    kNetworkServiceErrorEAPAuthentication = 8,
    kNetworkServiceErrorEAPLocalTLS = 9,
    kNetworkServiceErrorEAPRemoteTLS = 10,
    kNetworkServiceErrorHTTPGet = 11,
    kNetworkServiceErrorIPsecCertAuth = 12,
    kNetworkServiceErrorIPsecPSKAuth = 13,
    kNetworkServiceErrorInternal = 14,
    kNetworkServiceErrorNeedEVDO = 15,
    kNetworkServiceErrorNeedHomeNetwork = 16,
    kNetworkServiceErrorOTASP = 17,
    kNetworkServiceErrorOutOfRange = 18,
    kNetworkServiceErrorPPPAuth = 19,
    kNetworkServiceErrorPinMissing = 20,
    kNetworkServiceErrorUnknown = 21,
    kNetworkServiceErrorNotAssociated = 22,
    kNetworkServiceErrorNotAuthenticated = 23,
    kNetworkServiceErrorTooManySTAs = 24,
    kNetworkServiceErrorDisconnect = 25,
    kNetworkServiceErrorSimLocked = 26,
    kNetworkServiceErrorNotRegistered = 27,
    kNetworkServiceErrorMax
  };

  // Corresponds to RegulatoryDomain enum values in
  // /chromium/src/tools/metrics/histograms/enums.xml.
  // kRegDom00, kRegDom99, kRegDom98 and kRegDom97 are special alpha2 codes
  enum RegulatoryDomain {
    kRegDom00 = 1,
    kCountryCodeInvalid = 678,
    kRegDom99 = 679,
    kRegDom98 = 680,
    kRegDom97 = 681,
    kRegDomMaxValue
  };

  enum HS20Support {
    kHS20Unsupported = 0,
    kHS20VersionInvalid = 1,
    kHS20Version1 = 2,
    kHS20Version2 = 3,
    kHS20Version3 = 4,
    kHS20SupportMax
  };

  enum WiFiAdapterInAllowlist {
    kNotInAllowlist = 0,
    kInAVL = 1,
    kInAllowlist = 2,
    kAllowlistMax
  };

  // Our disconnect enumeration values are 0 (System Disconnect) and
  // 1 (User Disconnect), see histograms.xml, but Chrome needs a minimum
  // enum value of 1 and the minimum number of buckets needs to be 3 (see
  // histogram.h).  Instead of remapping System Disconnect to 1 and
  // User Disconnect to 2, we can just leave the enumerated values as-is
  // because Chrome implicitly creates a [0-1) bucket for us.  Using Min=1,
  // Max=2 and NumBuckets=3 gives us the following three buckets:
  // [0-1), [1-2), [2-INT_MAX).  We end up with an extra bucket [2-INT_MAX)
  // that we can safely ignore.
  static constexpr char kMetricDisconnectSuffix[] = "Disconnect";
  static constexpr int kMetricDisconnectMax = 2;
  static constexpr int kMetricDisconnectMin = 1;
  static constexpr int kMetricDisconnectNumBuckets = 3;
  static constexpr char kMetricSignalAtDisconnectSuffix[] =
      "SignalAtDisconnect";
  static constexpr int kMetricSignalAtDisconnectMin = 1;
  static constexpr int kMetricSignalAtDisconnectMax = 200;
  static constexpr int kMetricSignalAtDisconnectNumBuckets = 40;
  static constexpr char kMetricNetworkChannelSuffix[] = "Channel";
  static constexpr int kMetricNetworkChannelMax = kWiFiChannelMax;
  static constexpr char kMetricNetworkEapInnerProtocolSuffix[] =
      "EapInnerProtocol";
  static constexpr int kMetricNetworkEapInnerProtocolMax = kEapInnerProtocolMax;
  static constexpr char kMetricNetworkEapOuterProtocolSuffix[] =
      "EapOuterProtocol";
  static constexpr int kMetricNetworkEapOuterProtocolMax = kEapOuterProtocolMax;
  static constexpr char kMetricNetworkPhyModeSuffix[] = "PhyMode";
  static constexpr int kMetricNetworkPhyModeMax = kWiFiNetworkPhyModeMax;
  static constexpr char kMetricNetworkSecuritySuffix[] = "Security";
  static constexpr int kMetricNetworkSecurityMax = kWiFiSecurityMax;
  static constexpr char kMetricNetworkServiceErrorSuffix[] = "ServiceErrors";
  static constexpr char kMetricNetworkSignalStrengthSuffix[] = "SignalStrength";
  static constexpr int kMetricNetworkSignalStrengthMin = 1;
  static constexpr int kMetricNetworkSignalStrengthMax = 200;
  static constexpr int kMetricNetworkSignalStrengthNumBuckets = 40;

  // Histogram parameters for next two are the same as for
  // kMetricRememberedWiFiNetworkCount. Must be constexpr, for static
  // checking of format string. Must be defined inline, for constexpr.
  static constexpr char
      kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat[] =
          "Network.Shill.WiFi.RememberedSystemNetworkCount.%s";
  static constexpr char
      kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat[] =
          "Network.Shill.WiFi.RememberedUserNetworkCount.%s";
  static constexpr char kMetricRememberedWiFiNetworkCount[] =
      "Network.Shill.WiFi.RememberedNetworkCount";
  static constexpr int kMetricRememberedWiFiNetworkCountMax = 1024;
  static constexpr int kMetricRememberedWiFiNetworkCountMin = 1;
  static constexpr int kMetricRememberedWiFiNetworkCountNumBuckets = 32;
  static constexpr char kMetricHiddenSSIDNetworkCount[] =
      "Network.Shill.WiFi.HiddenSSIDNetworkCount";
  static constexpr char kMetricHiddenSSIDEverConnected[] =
      "Network.Shill.WiFi.HiddenSSIDEverConnected";
  static constexpr char kMetricWiFiCQMNotification[] =
      "Network.Shill.WiFi.CQMNotification";
  static constexpr char kMetricTimeOnlineSecondsSuffix[] = "TimeOnline";
  static constexpr int kMetricTimeOnlineSecondsMax = 8 * 60 * 60;  // 8 hours
  static constexpr int kMetricTimeOnlineSecondsMin = 1;

  static constexpr char kMetricTimeToConnectMillisecondsSuffix[] =
      "TimeToConnect";
  static constexpr int kMetricTimeToConnectMillisecondsMax =
      60 * 1000;  // 60 seconds
  static constexpr int kMetricTimeToConnectMillisecondsMin = 1;
  static constexpr int kMetricTimeToConnectMillisecondsNumBuckets = 60;
  static constexpr char kMetricTimeToScanAndConnectMillisecondsSuffix[] =
      "TimeToScanAndConnect";
  static constexpr char kMetricTimeToDropSeconds[] = "Network.Shill.TimeToDrop";
  static constexpr int kMetricTimeToDropSecondsMax = 8 * 60 * 60;  // 8 hours
  static constexpr int kMetricTimeToDropSecondsMin = 1;
  static constexpr char kMetricTimeToDisableMillisecondsSuffix[] =
      "TimeToDisable";
  static constexpr int kMetricTimeToDisableMillisecondsMax =
      60 * 1000;  // 60 seconds
  static constexpr int kMetricTimeToDisableMillisecondsMin = 1;
  static constexpr int kMetricTimeToDisableMillisecondsNumBuckets = 60;
  static constexpr char kMetricTimeToEnableMillisecondsSuffix[] =
      "TimeToEnable";
  static constexpr int kMetricTimeToEnableMillisecondsMax =
      60 * 1000;  // 60 seconds
  static constexpr int kMetricTimeToEnableMillisecondsMin = 1;
  static constexpr int kMetricTimeToEnableMillisecondsNumBuckets = 60;
  static constexpr char kMetricTimeToInitializeMillisecondsSuffix[] =
      "TimeToInitialize";
  static constexpr int kMetricTimeToInitializeMillisecondsMax =
      30 * 1000;  // 30 seconds
  static constexpr int kMetricTimeToInitializeMillisecondsMin = 1;
  static constexpr int kMetricTimeToInitializeMillisecondsNumBuckets = 30;
  static constexpr char kMetricTimeResumeToReadyMillisecondsSuffix[] =
      "TimeResumeToReady";
  static constexpr char kMetricTimeToConfigMillisecondsSuffix[] =
      "TimeToConfig";
  static constexpr char kMetricTimeToJoinMillisecondsSuffix[] = "TimeToJoin";
  static constexpr char kMetricTimeToOnlineMillisecondsSuffix[] =
      "TimeToOnline";
  static constexpr char kMetricTimeToPortalMillisecondsSuffix[] =
      "TimeToPortal";
  static constexpr char kMetricTimeToRedirectFoundMillisecondsSuffix[] =
      "TimeToRedirectFound";
  static constexpr char kMetricTimeToScanMillisecondsSuffix[] = "TimeToScan";
  static constexpr int kMetricTimeToScanMillisecondsMax =
      180 * 1000;  // 3 minutes
  static constexpr int kMetricTimeToScanMillisecondsMin = 1;
  static constexpr int kMetricTimeToScanMillisecondsNumBuckets = 90;
  static constexpr int kTimerHistogramMillisecondsMax = 45 * 1000;
  static constexpr int kTimerHistogramMillisecondsMin = 1;
  static constexpr int kTimerHistogramNumBuckets = 50;

  // The total number of portal detections attempted between the Connected
  // state and the Online state.  This includes both failure/timeout attempts
  // and the final successful attempt.
  static constexpr char kMetricPortalAttemptsToOnlineSuffix[] =
      "PortalAttemptsToOnline";
  static constexpr int kMetricPortalAttemptsToOnlineMax = 100;
  static constexpr int kMetricPortalAttemptsToOnlineMin = 1;
  static constexpr int kMetricPortalAttemptsToOnlineNumBuckets = 10;

  // The result of the portal detection.
  static constexpr char kMetricPortalResultSuffix[] = "PortalResult";

  static constexpr char kMetricScanResult[] = "Network.Shill.WiFi.ScanResult";
  static constexpr char kMetricWiFiScanTimeInEbusyMilliseconds[] =
      "Network.Shill.WiFi.ScanTimeInEbusy";

  static constexpr char kMetricPowerManagerKey[] = "metrics";

  // patchpanel::NeighborLinkMonitor statistics.
  static constexpr char kMetricNeighborLinkMonitorFailureSuffix[] =
      "NeighborLinkMonitorFailure";

  // Signal strength when link becomes unreliable (multiple link monitor
  // failures in short period of time).
  static constexpr char kMetricUnreliableLinkSignalStrengthSuffix[] =
      "UnreliableLinkSignalStrength";
  static constexpr int kMetricServiceSignalStrengthMin = 1;
  static constexpr int kMetricServiceSignalStrengthMax = 100;
  static constexpr int kMetricServiceSignalStrengthNumBuckets = 40;

  // AP 802.11r/k/v support statistics.
  static constexpr char kMetricAp80211kSupport[] =
      "Network.Shill.WiFi.Ap80211kSupport";
  static constexpr char kMetricAp80211rSupport[] =
      "Network.Shill.WiFi.Ap80211rSupport";
  static constexpr char kMetricAp80211vDMSSupport[] =
      "Network.Shill.WiFi.Ap80211vDMSSupport";
  static constexpr char kMetricAp80211vBSSMaxIdlePeriodSupport[] =
      "Network.Shill.WiFi.Ap80211vBSSMaxIdlePeriodSupport";
  static constexpr char kMetricAp80211vBSSTransitionSupport[] =
      "Network.Shill.WiFi.Ap80211vBSSTransitionSupport";

  static constexpr char kMetricLinkClientDisconnectReason[] =
      "Network.Shill.WiFi.ClientDisconnectReason";
  static constexpr char kMetricLinkApDisconnectReason[] =
      "Network.Shill.WiFi.ApDisconnectReason";
  static constexpr char kMetricLinkClientDisconnectType[] =
      "Network.Shill.WiFi.ClientDisconnectType";
  static constexpr char kMetricLinkApDisconnectType[] =
      "Network.Shill.WiFi.ApDisconnectType";

  // 802.11 Status Codes for auth/assoc failures
  static constexpr char kMetricWiFiAssocFailureType[] =
      "Network.Shill.WiFi.AssocFailureType";
  static constexpr char kMetricWiFiAuthFailureType[] =
      "Network.Shill.WiFi.AuthFailureType";

  // Roam time for FT and non-FT key management suites.
  static constexpr char kMetricWifiRoamTimePrefix[] =
      "Network.Shill.WiFi.RoamTime";
  static constexpr int kMetricWifiRoamTimeMillisecondsMax = 1000;
  static constexpr int kMetricWifiRoamTimeMillisecondsMin = 1;
  static constexpr int kMetricWifiRoamTimeNumBuckets = 20;

  // Roam completions for FT and non-FT key management suites.
  static constexpr char kMetricWifiRoamCompletePrefix[] =
      "Network.Shill.WiFi.RoamComplete";

  // Session Lengths for FT and non-FT key management suites.
  static constexpr char kMetricWifiSessionLengthPrefix[] =
      "Network.Shill.WiFi.SessionLength";
  static constexpr int kMetricWifiSessionLengthMillisecondsMax = 10000;
  static constexpr int kMetricWifiSessionLengthMillisecondsMin = 1;
  static constexpr int kMetricWifiSessionLengthNumBuckets = 20;

  // Suffixes for roam histograms.
  static constexpr char kMetricWifiPSKSuffix[] = "PSK";
  static constexpr char kMetricWifiFTPSKSuffix[] = "FTPSK";
  static constexpr char kMetricWifiEAPSuffix[] = "EAP";
  static constexpr char kMetricWifiFTEAPSuffix[] = "FTEAP";

  static constexpr char kMetricApChannelSwitch[] =
      "Network.Shill.WiFi.ApChannelSwitch";

  // Shill suspend action statistics.
  static constexpr char kMetricSuspendActionTimeTaken[] =
      "Network.Shill.SuspendActionTimeTaken";
  static constexpr char kMetricSuspendActionResult[] =
      "Network.Shill.SuspendActionResult";
  static constexpr int kMetricSuspendActionTimeTakenMillisecondsMax = 20000;
  static constexpr int kMetricSuspendActionTimeTakenMillisecondsMin = 1;

  // Cellular specific statistics.
  static constexpr char kMetricCellular3GPPRegistrationDelayedDrop[] =
      "Network.Shill.Cellular.3GPPRegistrationDelayedDrop";
  static constexpr char kMetricCellularDrop[] = "Network.Shill.Cellular.Drop";
  static constexpr char kMetricCellularConnectResult[] =
      "Network.Shill.Cellular.ConnectResult";
  static constexpr char kMetricCellularOutOfCreditsReason[] =
      "Network.Shill.Cellular.OutOfCreditsReason";
  static constexpr char kMetricCellularSignalStrengthBeforeDrop[] =
      "Network.Shill.Cellular.SignalStrengthBeforeDrop";
  static constexpr int kMetricCellularSignalStrengthBeforeDropMax = 100;
  static constexpr int kMetricCellularSignalStrengthBeforeDropMin = 1;
  static constexpr int kMetricCellularSignalStrengthBeforeDropNumBuckets = 10;

  // Profile statistics.
  static constexpr char kMetricCorruptedProfile[] =
      "Network.Shill.CorruptedProfile";

  // VPN connection statistics.
  static constexpr char kMetricVpnDriver[] = "Network.Shill.Vpn.Driver";
  static constexpr int kMetricVpnDriverMax = kVpnDriverMax;
  static constexpr char kMetricVpnRemoteAuthenticationType[] =
      "Network.Shill.Vpn.RemoteAuthenticationType";
  static constexpr int kMetricVpnRemoteAuthenticationTypeMax =
      kVpnRemoteAuthenticationTypeMax;
  static constexpr char kMetricVpnUserAuthenticationType[] =
      "Network.Shill.Vpn.UserAuthenticationType";
  static constexpr int kMetricVpnUserAuthenticationTypeMax =
      kVpnUserAuthenticationTypeMax;

  // IKEv2 connection statistics.
  static constexpr char kMetricVpnIkev2AuthenticationType[] =
      "Network.Shill.Vpn.Ikev2.AuthenticationType";
  static constexpr int kMetricVpnIkev2AuthenticationMax =
      kVpnIpsecAuthenticationTypeMax;
  static constexpr char kMetricVpnIkev2IkeEncryptionAlgorithm[] =
      "Network.Shill.Vpn.Ikev2.IkeEncryptionAlgorithm";
  static constexpr int kMetricVpnIkev2IkeEncryptionAlgorithmMax =
      kVpnIpsecEncryptionAlgorithmMax;
  static constexpr char kMetricVpnIkev2IkeIntegrityAlgorithm[] =
      "Network.Shill.Vpn.Ikev2.IkeIntegrityAlgorithm";
  static constexpr int kMetricVpnIkev2IkeIntegrityAlgorithmMax =
      kVpnIpsecIntegrityAlgorithmMax;
  static constexpr char kMetricVpnIkev2IkeDHGroup[] =
      "Network.Shill.Vpn.Ikev2.IkeDHGroup";
  static constexpr int kMetricVpnIkev2IkeDHGroupMax = kVpnIpsecDHGroupMax;
  static constexpr char kMetricVpnIkev2EspEncryptionAlgorithm[] =
      "Network.Shill.Vpn.Ikev2.EspEncryptionAlgorithm";
  static constexpr int kMetricVpnIkev2EspEncryptionAlgorithmMax =
      kVpnIpsecEncryptionAlgorithmMax;
  static constexpr char kMetricVpnIkev2EspIntegrityAlgorithm[] =
      "Network.Shill.Vpn.Ikev2.EspIntegrityAlgorithm";
  static constexpr int kMetricVpnIkev2EspIntegrityAlgorithmMax =
      kVpnIpsecIntegrityAlgorithmMax;
  static constexpr char kMetricVpnIkev2EndReason[] =
      "Network.Shill.Vpn.Ikev2.EndReason";
  static constexpr int kMetricVpnIkev2EndReasonMax = kNetworkServiceErrorMax;

  // L2TP/IPsec connection statistics.
  static constexpr char kMetricVpnL2tpIpsecTunnelGroupUsage[] =
      "Network.Shill.Vpn.L2tpIpsecTunnelGroupUsage";
  static constexpr int kMetricVpnL2tpIpsecTunnelGroupUsageMax =
      kVpnL2tpIpsecTunnelGroupUsageMax;
  static constexpr char kMetricVpnL2tpIpsecIkeEncryptionAlgorithm[] =
      "Network.Shill.Vpn.L2tpIpsec.IkeEncryptionAlgorithm";
  static constexpr int kMetricVpnL2tpIpsecIkeEncryptionAlgorithmMax =
      kVpnIpsecEncryptionAlgorithmMax;
  static constexpr char kMetricVpnL2tpIpsecIkeIntegrityAlgorithm[] =
      "Network.Shill.Vpn.L2tpIpsec.IkeIntegrityAlgorithm";
  static constexpr int kMetricVpnL2tpIpsecIkeIntegrityAlgorithmMax =
      kVpnIpsecIntegrityAlgorithmMax;
  static constexpr char kMetricVpnL2tpIpsecIkeDHGroup[] =
      "Network.Shill.Vpn.L2tpIpsec.IkeDHGroup";
  static constexpr int kMetricVpnL2tpIpsecIkeDHGroupMax = kVpnIpsecDHGroupMax;
  static constexpr char kMetricVpnL2tpIpsecEspEncryptionAlgorithm[] =
      "Network.Shill.Vpn.L2tpIpsec.EspEncryptionAlgorithm";
  static constexpr int kMetricVpnL2tpIpsecEspEncryptionAlgorithmMax =
      kVpnIpsecEncryptionAlgorithmMax;
  static constexpr char kMetricVpnL2tpIpsecEspIntegrityAlgorithm[] =
      "Network.Shill.Vpn.L2tpIpsec.EspIntegrityAlgorithm";
  static constexpr int kMetricVpnL2tpIpsecEspIntegrityAlgorithmMax =
      kVpnIpsecIntegrityAlgorithmMax;
  // Temporary metrics for comparing the robustness of the two L2TP/IPsec
  // drivers (b/204261554).
  static constexpr char kMetricVpnL2tpIpsecStrokeEndReason[] =
      "Network.Shill.Vpn.L2tpIpsec.StrokeEndReason";
  static constexpr int kMetricVpnL2tpIpsecStrokeEndReasonMax =
      kNetworkServiceErrorMax;
  static constexpr char kMetricVpnL2tpIpsecSwanctlEndReason[] =
      "Network.Shill.Vpn.L2tpIpsec.SwanctlEndReason";
  static constexpr int kMetricVpnL2tpIpsecSwanctlEndReasonMax =
      kNetworkServiceErrorMax;

  // OpenVPN connection statistics.
  // Cipher algorithm used after negotiating with server.
  static constexpr char kMetricVpnOpenVPNCipher[] =
      "Network.Shill.Vpn.OpenVPNCipher";
  static constexpr int kMetricVpnOpenVPNCipherMax = kVpnOpenVPNCipherMax;

  // WireGuard connection statistics.
  // Key pair source (e.g., user input) used in a WireGuard Connection.
  static constexpr char kMetricVpnWireGuardKeyPairSource[] =
      "Network.Shill.Vpn.WireGuardKeyPairSource";
  static constexpr int kMetricVpnWireGuardKeyPairSourceMax =
      kVpnWireGuardKeyPairSourceMax;
  // Number of peers used in a WireGuard connection.
  static constexpr char kMetricVpnWireGuardPeersNum[] =
      "Network.Shill.Vpn.WireGuardPeersNum";
  static constexpr int kMetricVpnWireGuardPeersNumMin = 1;
  static constexpr int kMetricVpnWireGuardPeersNumMax = 10;
  static constexpr int kMetricVpnWireGuardPeersNumNumBuckets = 11;
  // Allowed IPs type used in a WireGuard connection.
  static constexpr char kMetricVpnWireGuardAllowedIPsType[] =
      "Network.Shill.Vpn.WireGuardAllowedIPsType";
  static constexpr int kMetricVpnWireGuardAllowedIPsTypeMax =
      kVpnWireGuardAllowedIPsTypeMax;

  // The length in seconds of a lease that has expired while the DHCP client was
  // attempting to renew the lease. CL:557297 changed the number of buckets for
  // the 'ExpiredLeaseLengthSeconds' metric. That would lead to confusing
  // display of samples collected before and after the change. To avoid that,
  // the 'ExpiredLeaseLengthSeconds' metric is renamed to
  // 'ExpiredLeaseLengthSeconds2'.
  static constexpr char kMetricExpiredLeaseLengthSecondsSuffix[] =
      "ExpiredLeaseLengthSeconds2";
  static constexpr int kMetricExpiredLeaseLengthSecondsMax =
      7 * 24 * 60 * 60;  // 7 days
  static constexpr int kMetricExpiredLeaseLengthSecondsMin = 1;
  static constexpr int kMetricExpiredLeaseLengthSecondsNumBuckets = 100;

  // Number of wifi services available when auto-connect is initiated.
  static constexpr char kMetricWifiAutoConnectableServices[] =
      "Network.Shill.WiFi.AutoConnectableServices";
  static constexpr int kMetricWifiAutoConnectableServicesMax = 50;
  static constexpr int kMetricWifiAutoConnectableServicesMin = 1;
  static constexpr int kMetricWifiAutoConnectableServicesNumBuckets = 10;

  // Number of BSSes available for a wifi service when we attempt to connect
  // to that service.
  static constexpr char kMetricWifiAvailableBSSes[] =
      "Network.Shill.WiFi.AvailableBSSesAtConnect";
  static constexpr int kMetricWifiAvailableBSSesMax = 50;
  static constexpr int kMetricWifiAvailableBSSesMin = 1;
  static constexpr int kMetricWifiAvailableBSSesNumBuckets = 10;

  // Wifi TX bitrate in Mbps.
  static constexpr char kMetricWifiTxBitrate[] =
      "Network.Shill.WiFi.TransmitBitrateMbps";
  static constexpr int kMetricWifiTxBitrateMax = 7000;
  static constexpr int kMetricWifiTxBitrateMin = 1;
  static constexpr int kMetricWifiTxBitrateNumBuckets = 100;

  // User-initiated wifi connection attempt result.
  static constexpr char kMetricWifiUserInitiatedConnectionResult[] =
      "Network.Shill.WiFi.UserInitiatedConnectionResult";

  // The reason of failed user-initiated wifi connection attempt.
  static constexpr char kMetricWifiUserInitiatedConnectionFailureReason[] =
      "Network.Shill.WiFi.UserInitiatedConnectionFailureReason";

  // Number of attempts made to connect to supplicant before success (max ==
  // failure).
  static constexpr char kMetricWifiSupplicantAttempts[] =
      "Network.Shill.WiFi.SupplicantAttempts";
  static constexpr int kMetricWifiSupplicantAttemptsMax = 10;
  static constexpr int kMetricWifiSupplicantAttemptsMin = 1;
  static constexpr int kMetricWifiSupplicantAttemptsNumBuckets = 11;

  // Device's connection status.
  static constexpr char kMetricDeviceConnectionStatus[] =
      "Network.Shill.DeviceConnectionStatus";

  // Assigned MTU values from PPP.
  static constexpr char kMetricPPPMTUValue[] = "Network.Shill.PPPMTUValue";

  // Network connection IP type.
  static constexpr char kMetricNetworkConnectionIPTypeSuffix[] =
      "NetworkConnectionIPType";

  // IPv6 connectivity status.
  static constexpr char kMetricIPv6ConnectivityStatusSuffix[] =
      "IPv6ConnectivityStatus";

  // Device presence.
  static constexpr char kMetricDevicePresenceStatusSuffix[] =
      "DevicePresenceStatus";

  // Connection diagnostics issue.
  static constexpr char kMetricConnectionDiagnosticsIssue[] =
      "Network.Shill.ConnectionDiagnosticsIssue";

  // Portal detection results.
  static constexpr char kMetricPortalDetectionMultiProbeResult[] =
      "Network.Shill.PortalDetectionMultiProbeResult";

  // Wireless regulatory domain metric.
  static constexpr char kMetricRegulatoryDomain[] =
      "Network.Shill.WiFi.RegulatoryDomain";

  // Hotspot 2.0 version number metric.
  static constexpr char kMetricHS20Support[] = "Network.Shill.WiFi.HS20Support";

  // MBO support metric.
  static constexpr char kMetricMBOSupport[] = "Network.Shill.WiFi.MBOSupport";

  // Seconds between latest WiFi rekey attempt and service failure.
  static constexpr char kMetricTimeFromRekeyToFailureSeconds[] =
      "Network.Shill.WiFi.TimeFromRekeyToFailureSeconds";
  static constexpr int kMetricTimeFromRekeyToFailureSecondsMin = 0;
  static constexpr int kMetricTimeFromRekeyToFailureSecondsMax = 180;
  static constexpr int kMetricTimeFromRekeyToFailureSecondsNumBuckets = 30;

  // Is the WiFi adapter detected on the system in the allowlist of adapters
  // that can be reported through structured metrics or not?
  static constexpr char kMetricAdapterInfoAllowlisted[] =
      "Network.Shill.WiFi.AdapterAllowlisted";

  // Version number of the format of WiFi structured metrics. Changed when the
  // formatting of the metrics changes, so that the server-side code knows
  // which fields to expect.
  static constexpr int kWiFiStructuredMetricsVersion = 1;

  // When emitting WiFi structured metrics, if we encounter errors and the
  // numeric values of some of the fields can not be populated, use this as
  // value for the field.
  static constexpr int kWiFiStructuredMetricsErrorValue = -1;

  struct WiFiAdapterInfo {
    int vendor_id;
    int product_id;
    int subsystem_id;
  };

  Metrics();
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  virtual ~Metrics();

  // Converts the WiFi frequency into the associated UMA channel enumerator.
  static WiFiChannel WiFiFrequencyToChannel(uint16_t frequency);

  // Converts WiFi Channel to the associated frequency range.
  static WiFiFrequencyRange WiFiChannelToFrequencyRange(WiFiChannel channel);

  // Converts a flimflam security string into its UMA security enumerator.
  static WiFiSecurity WiFiSecurityStringToEnum(const std::string& security);

  // Converts a flimflam EAP outer protocol string into its UMA enumerator.
  static EapOuterProtocol EapOuterProtocolStringToEnum(
      const std::string& outer);

  // Converts a flimflam EAP inner protocol string into its UMA enumerator.
  static EapInnerProtocol EapInnerProtocolStringToEnum(
      const std::string& inner);

  // Converts portal detection result to UMA portal result enumerator.
  static PortalResult PortalDetectionResultToEnum(
      const PortalDetector::Result& result);

  // Converts service connect failure to UMA service error enumerator.
  static NetworkServiceError ConnectFailureToServiceErrorEnum(
      Service::ConnectFailure failure);

  // Registers a service with this object so it can use the timers to track
  // state transition metrics.
  void RegisterService(const Service& service);

  // Deregisters the service from this class.  All state transition timers
  // will be removed.
  void DeregisterService(const Service& service);

  // Tracks the time it takes |service| to go from |start_state| to
  // |stop_state|.  When |stop_state| is reached, the time is sent to UMA.
  virtual void AddServiceStateTransitionTimer(const Service& service,
                                              const std::string& histogram_name,
                                              Service::ConnectState start_state,
                                              Service::ConnectState stop_state);

  // Specializes |metric_suffix| for the specified |technology_id|.
  std::string GetFullMetricName(const char* metric_suffix,
                                Technology technology_id);

  // Implements DefaultServiceObserver.
  void OnDefaultLogicalServiceChanged(
      const ServiceRefPtr& logical_service) override;
  void OnDefaultPhysicalServiceChanged(
      const ServiceRefPtr& physical_service) override;

  // Notifies this object that |service| state has changed.
  virtual void NotifyServiceStateChanged(const Service& service,
                                         Service::ConnectState new_state);

  // Notifies this object that |service| has been disconnected.
  void NotifyServiceDisconnect(const Service& service);

  // Notifies this object of power at disconnect.
  void NotifySignalAtDisconnect(const Service& service,
                                int16_t signal_strength);

  // Notifies this object of the end of a suspend attempt.
  void NotifySuspendDone();

  // Notifies this object that suspend actions started executing.
  void NotifySuspendActionsStarted();

  // Notifies this object that suspend actions have been completed.
  // |success| is true, if the suspend actions completed successfully.
  void NotifySuspendActionsCompleted(bool success);

  // Notifies this object of a failure in patchpanel::NeighborLinkMonitor.
  void NotifyNeighborLinkMonitorFailure(
      Technology technology,
      IPAddress::Family family,
      patchpanel::NeighborReachabilityEventSignal::Role role);

  // Notifies this object that an AP was discovered and of that AP's 802.11k
  // support.
  void NotifyAp80211kSupport(bool neighbor_list_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11r
  // support.
  void NotifyAp80211rSupport(bool ota_ft_supported, bool otds_ft_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11v
  // DMS support.
  void NotifyAp80211vDMSSupport(bool dms_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11v
  // BSS Max Idle Period support.
  void NotifyAp80211vBSSMaxIdlePeriodSupport(
      bool bss_max_idle_period_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11v
  // BSS Transition support.
  void NotifyAp80211vBSSTransitionSupport(bool bss_transition_supported);

#if !defined(DISABLE_WIFI)
  // Notifies this object of WiFi disconnect.
  virtual void Notify80211Disconnect(WiFiDisconnectByWhom by_whom,
                                     IEEE_80211::WiFiReasonCode reason);
#endif  // DISABLE_WIFI

  // Notifies that WiFi tried to set up supplicant too many times.
  void NotifyWiFiSupplicantAbort();

  // Notifies that WiFi successfully set up supplicant after some number of
  // |attempts|.
  virtual void NotifyWiFiSupplicantSuccess(int attempts);

  // Notifies this object that an AP has switched channels.
  void NotifyApChannelSwitch(uint16_t frequency, uint16_t new_frequency);

  // Registers a device with this object so the device can use the timers to
  // track state transition metrics.
  void RegisterDevice(int interface_index, Technology technology);

  // Checks to see if the device has already been registered.
  bool IsDeviceRegistered(int interface_index, Technology technology);

  // Deregisters the device from this class.  All state transition timers
  // will be removed.
  virtual void DeregisterDevice(int interface_index);

  // Notifies this object that a device has been initialized.
  void NotifyDeviceInitialized(int interface_index);

  // Notifies this object that a device has started the enable process.
  void NotifyDeviceEnableStarted(int interface_index);

  // Notifies this object that a device has completed the enable process.
  void NotifyDeviceEnableFinished(int interface_index);

  // Notifies this object that a device has started the disable process.
  void NotifyDeviceDisableStarted(int interface_index);

  // Notifies this object that a device has completed the disable process.
  void NotifyDeviceDisableFinished(int interface_index);

  // Notifies this object that a device has started the scanning process.
  virtual void NotifyDeviceScanStarted(int interface_index);

  // Notifies this object that a device has completed the scanning process.
  virtual void NotifyDeviceScanFinished(int interface_index);

  // Terminates an underway scan (does nothing if a scan wasn't underway).
  virtual void ResetScanTimer(int interface_index);

  // Notifies this object that a device has started the connect process.
  virtual void NotifyDeviceConnectStarted(int interface_index);

  // Notifies this object that a device has completed the connect process.
  virtual void NotifyDeviceConnectFinished(int interface_index);

  // Resets both the connect_timer and the scan_connect_timer the timer (the
  // latter so that a future connect will not erroneously be associated with
  // the previous scan).
  virtual void ResetConnectTimer(int interface_index);

  // Notifies this object that a cellular device has been dropped by the
  // network.
  void NotifyCellularDeviceDrop(const std::string& network_technology,
                                uint16_t signal_strength);

  // Notifies this object of the resulting status of a cellular connection
  void NotifyCellularConnectionResult(Error::Type error);

  // Notifies this object of the resulting status of a cellular connection
  virtual void NotifyDetailedCellularConnectionResult(
      Error::Type error,
      const std::string& detailed_error,
      const std::string& uuid,
      const shill::Stringmap& apn_info,
      IPConfig::Method ipv4_config_method,
      IPConfig::Method ipv6_config_method,
      const std::string& home_mccmnc,
      const std::string& serving_mccmnc,
      const std::string& roaming_state,
      bool use_attach_apn,
      uint32_t tech_used,
      uint32_t iccid_len,
      uint32_t sim_type,
      uint32_t modem_state,
      int interface_index);

  // Notifies this object about 3GPP registration drop events.
  virtual void Notify3GPPRegistrationDelayedDropPosted();
  virtual void Notify3GPPRegistrationDelayedDropCanceled();

  // Notifies this object that a cellular service has been marked as
  // out-of-credits.
  void NotifyCellularOutOfCredits(Metrics::CellularOutOfCreditsReason reason);

  // Notifies this object about number of wifi services available for auto
  // connect when auto-connect is initiated.
  virtual void NotifyWifiAutoConnectableServices(int num_services);

  // Notifies this object about number of BSSes available for a wifi service
  // when attempt to connect to that service.
  virtual void NotifyWifiAvailableBSSes(int num_services);

  // Notifies this object about WIFI TX bitrate in Mbps.
  virtual void NotifyWifiTxBitrate(int bitrate);

  // Notifies this object about the result of user-initiated connection
  // attempt.
  virtual void NotifyUserInitiatedConnectionResult(const std::string& name,
                                                   int result);

  // Notifies this object about the reason of failed user-initiated connection
  // attempt.
  virtual void NotifyUserInitiatedConnectionFailureReason(
      const std::string& name, const Service::ConnectFailure failure);

  // Notifies this object about a corrupted profile.
  virtual void NotifyCorruptedProfile();

  // Notifies this object about current connection status (online vs offline).
  virtual void NotifyDeviceConnectionStatus(Metrics::ConnectionStatus status);

  // Notifies this object about the IP type of the current network connection.
  virtual void NotifyNetworkConnectionIPType(Technology technology_id,
                                             NetworkConnectionIPType type);

  // Notifies this object about the IPv6 connectivity status.
  virtual void NotifyIPv6ConnectivityStatus(Technology technology_id,
                                            bool status);

  // Notifies this object about the presence of given technology type device.
  virtual void NotifyDevicePresenceStatus(Technology technology_id,
                                          bool status);

  // Notifies this object about the signal strength when link is unreliable.
  virtual void NotifyUnreliableLinkSignalStrength(Technology technology_id,
                                                  int signal_strength);

  // Sends linear histogram data to UMA.
  virtual bool SendEnumToUMA(const std::string& name, int sample, int max);

  // Sends bool to UMA.
  virtual bool SendBoolToUMA(const std::string& name, bool b);

  // Send logarithmic histogram data to UMA.
  virtual bool SendToUMA(
      const std::string& name, int sample, int min, int max, int num_buckets);

  // Sends sparse histogram data to UMA.
  virtual bool SendSparseToUMA(const std::string& name, int sample);

  // Notifies this object that connection diagnostics have been performed, and
  // the connection issue that was diagnosed is |issue|.
  virtual void NotifyConnectionDiagnosticsIssue(const std::string& issue);

  // Notifies this object that a portal detection trial has finished with probe
  // results from both the HTTP probe and the HTTPS probe.
  virtual void NotifyPortalDetectionMultiProbeResult(
      const PortalDetector::Result& result);

  // Notifies this object that of the HS20 support of an access that has
  // been connected to.
  void NotifyHS20Support(bool hs20_supported, int hs20_version_number);

  // Calculate Regulatory domain value given two letter country code.
  // Return value corresponds to Network.Shill.WiFi.RegulatoryDomain histogram
  // buckets. The full enum can be found in
  // /chromium/src/tools/metrics/histograms/enums.xml.
  static int GetRegulatoryDomainValue(std::string country_code);

  // Notifies this object of the MBO support of the access point that has been
  // connected to.
  void NotifyMBOSupport(bool mbo_support);

  // Emits the |WiFiAdapterStateChanged| structured event that notifies that
  // the WiFi adapter has been enabled or disabled. Includes the IDs describing
  // the type of the adapter (e.g. PCI IDs).
  mockable void NotifyWiFiAdapterStateChanged(bool enabled,
                                              const WiFiAdapterInfo& info);

  enum ConnectionAttemptType {
    kAttemptTypeUnknown = 0,
    kAttemptTypeUserInitiated = 1,
    kAttemptTypeAuto = 2
  };

  enum SSIDProvisioningMode {
    kProvisionUnknown = 0,
    kProvisionManual = 1,
    kProvisionPolicy = 2,
    kProvisionSync = 3
  };

  struct WiFiConnectionAttemptInfo {
    ConnectionAttemptType type;
    WiFiNetworkPhyMode mode;
    WiFiSecurity security;
    EapInnerProtocol eap_inner;
    EapOuterProtocol eap_outer;
    WiFiFrequencyRange band;
    WiFiChannel channel;
    int rssi;
    std::string ssid;
    std::string bssid;
    SSIDProvisioningMode provisioning_mode;
    bool ssid_hidden;
    int ap_oui;
    struct ApSupportedFeatures {
      struct Ap80211krv {
        int neighbor_list_supported = kWiFiStructuredMetricsErrorValue;
        int ota_ft_supported = kWiFiStructuredMetricsErrorValue;
        int otds_ft_supported = kWiFiStructuredMetricsErrorValue;
        int dms_supported = kWiFiStructuredMetricsErrorValue;
        int bss_max_idle_period_supported = kWiFiStructuredMetricsErrorValue;
        int bss_transition_supported = kWiFiStructuredMetricsErrorValue;
      } krv_info;
      struct ApHS20 {
        int supported = kWiFiStructuredMetricsErrorValue;
        int version = kWiFiStructuredMetricsErrorValue;
      } hs20_info;
      int mbo_supported = kWiFiStructuredMetricsErrorValue;
    } ap_features;
  };

  static WiFiConnectionAttemptInfo::ApSupportedFeatures ConvertEndPointFeatures(
      const WiFiEndpoint* ep);

  // Emits the |WiFiConnectionAttempt| structured event that notifies that the
  // device is attempting to connect to an AP. It describes the parameters of
  // the connection (channel/band, security mode, etc.).
  virtual void NotifyWiFiConnectionAttempt(
      const WiFiConnectionAttemptInfo& info);

  // Emits the |WiFiConnectionAttemptResult| structured event that describes
  // the result of the corresponding |WiFiConnectionAttempt| event.
  virtual void NotifyWiFiConnectionAttemptResult(
      NetworkServiceError result_code);

  // Returns a persistent hash to be used to uniquely identify an APN.
  static int64_t HashApn(const std::string& uuid,
                         const std::string& apn_name,
                         const std::string& username,
                         const std::string& password);

  // Notifies this object of the time elapsed between a WiFi service failure
  // after the latest rekey event.
  void NotifyWiFiServiceFailureAfterRekey(int seconds);

 private:
  friend class MetricsTest;
  FRIEND_TEST(MetricsTest, FrequencyToChannel);
  FRIEND_TEST(MetricsTest, ResetConnectTimer);
  FRIEND_TEST(MetricsTest, ServiceFailure);
  FRIEND_TEST(MetricsTest, TimeOnlineTimeToDrop);
  FRIEND_TEST(MetricsTest, TimeToConfig);
  FRIEND_TEST(MetricsTest, TimeToOnline);
  FRIEND_TEST(MetricsTest, TimeToPortal);
  FRIEND_TEST(MetricsTest, TimeToScanIgnore);
  FRIEND_TEST(MetricsTest, WiFiServicePostReady);
  FRIEND_TEST(MetricsTest, NotifySuspendActionsCompleted_Success);
  FRIEND_TEST(MetricsTest, NotifySuspendActionsCompleted_Failure);
  FRIEND_TEST(MetricsTest, NotifySuspendActionsStarted);
  FRIEND_TEST(WiFiMainTest, GetGeolocationObjects);

  using TimerReporters =
      std::vector<std::unique_ptr<chromeos_metrics::TimerReporter>>;
  using TimerReportersList = std::list<chromeos_metrics::TimerReporter*>;
  using TimerReportersByState =
      std::map<Service::ConnectState, TimerReportersList>;
  struct ServiceMetrics {
    // All TimerReporter objects are stored in |timers| which owns the objects.
    // |start_on_state| and |stop_on_state| contain pointers to the
    // TimerReporter objects and control when to start and stop the timers.
    TimerReporters timers;
    TimerReportersByState start_on_state;
    TimerReportersByState stop_on_state;
  };
  using ServiceMetricsLookupMap =
      std::map<const Service*, std::unique_ptr<ServiceMetrics>>;

  struct DeviceMetrics {
    DeviceMetrics() {}
    Technology technology;
    std::unique_ptr<chromeos_metrics::TimerReporter> initialization_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> enable_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> disable_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> scan_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> connect_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> scan_connect_timer;
  };
  using DeviceMetricsLookupMap =
      std::map<const int, std::unique_ptr<DeviceMetrics>>;

  static constexpr uint16_t kWiFiBandwidth5MHz = 5;
  static constexpr uint16_t kWiFiBandwidth20MHz = 20;
  static constexpr uint16_t kWiFiFrequency2412 = 2412;
  static constexpr uint16_t kWiFiFrequency2472 = 2472;
  static constexpr uint16_t kWiFiFrequency2484 = 2484;
  static constexpr uint16_t kWiFiFrequency5170 = 5170;
  static constexpr uint16_t kWiFiFrequency5180 = 5180;
  static constexpr uint16_t kWiFiFrequency5230 = 5230;
  static constexpr uint16_t kWiFiFrequency5240 = 5240;
  static constexpr uint16_t kWiFiFrequency5320 = 5320;
  static constexpr uint16_t kWiFiFrequency5500 = 5500;
  static constexpr uint16_t kWiFiFrequency5700 = 5700;
  static constexpr uint16_t kWiFiFrequency5745 = 5745;
  static constexpr uint16_t kWiFiFrequency5825 = 5825;
  static constexpr uint16_t kWiFiFrequency5955 = 5955;
  static constexpr uint16_t kWiFiFrequency7115 = 7115;

  static constexpr char kBootIdProcPath[] = "/proc/sys/kernel/random/boot_id";

  void InitializeCommonServiceMetrics(const Service& service);
  void UpdateServiceStateTransitionMetrics(ServiceMetrics* service_metrics,
                                           Service::ConnectState new_state);
  void SendServiceFailure(const Service& service);

  DeviceMetrics* GetDeviceMetrics(int interface_index) const;

  // For unit test purposes.
  void set_library(MetricsLibraryInterface* library);
  void set_time_online_timer(chromeos_metrics::Timer* timer) {
    time_online_timer_.reset(timer);  // Passes ownership
  }
  void set_time_to_drop_timer(chromeos_metrics::Timer* timer) {
    time_to_drop_timer_.reset(timer);  // Passes ownership
  }
  void set_time_resume_to_ready_timer(chromeos_metrics::Timer* timer) {
    time_resume_to_ready_timer_.reset(timer);  // Passes ownership
  }
  void set_time_suspend_actions_timer(chromeos_metrics::Timer* timer) {
    time_suspend_actions_timer.reset(timer);  // Passes ownership
  }
  void set_time_to_scan_timer(int interface_index,
                              chromeos_metrics::TimerReporter* timer) {
    DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
    device_metrics->scan_timer.reset(timer);  // Passes ownership
  }
  void set_time_to_connect_timer(int interface_index,
                                 chromeos_metrics::TimerReporter* timer) {
    DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
    device_metrics->connect_timer.reset(timer);  // Passes ownership
  }
  void set_time_to_scan_connect_timer(int interface_index,
                                      chromeos_metrics::TimerReporter* timer) {
    DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
    device_metrics->scan_connect_timer.reset(timer);  // Passes ownership
  }

  static std::string GetBootId();

  // |library_| points to |metrics_library_| when shill runs normally.
  // However, in order to allow for unit testing, we point |library_| to a
  // MetricsLibraryMock object instead.
  MetricsLibrary metrics_library_;
  MetricsLibraryInterface* library_;
  ServiceMetricsLookupMap services_metrics_;
  Technology last_default_technology_;
  bool was_last_online_;
  std::unique_ptr<chromeos_metrics::Timer> time_online_timer_;
  std::unique_ptr<chromeos_metrics::Timer> time_to_drop_timer_;
  std::unique_ptr<chromeos_metrics::Timer> time_resume_to_ready_timer_;
  std::unique_ptr<chromeos_metrics::Timer> time_suspend_actions_timer;
  DeviceMetricsLookupMap devices_metrics_;
  Time* time_;
};

}  // namespace shill

#endif  // SHILL_METRICS_H_
