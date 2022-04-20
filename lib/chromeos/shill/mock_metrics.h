// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_METRICS_H_
#define SHILL_MOCK_METRICS_H_

#include <string>

#include "shill/metrics.h"

#include <gmock/gmock.h>

namespace shill {

class MockMetrics : public Metrics {
 public:
  MockMetrics();
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;

  ~MockMetrics() override;

  MOCK_METHOD(void,
              AddServiceStateTransitionTimer,
              (const Service&,
               const std::string&,
               Service::ConnectState,
               Service::ConnectState),
              (override));
  MOCK_METHOD(void, DeregisterDevice, (int), (override));
  MOCK_METHOD(void, NotifyDeviceScanStarted, (int), (override));
  MOCK_METHOD(void, NotifyDeviceScanFinished, (int), (override));
  MOCK_METHOD(void, ResetScanTimer, (int), (override));
  MOCK_METHOD(void, NotifyDeviceConnectStarted, (int), (override));
  MOCK_METHOD(void, NotifyDeviceConnectFinished, (int), (override));
  MOCK_METHOD(void, ResetConnectTimer, (int), (override));
  MOCK_METHOD(void,
              NotifyDetailedCellularConnectionResult,
              (Error::Type,
               const std::string&,
               const std::string&,
               const shill::Stringmap&,
               IPConfig::Method,
               IPConfig::Method,
               const std::string&,
               const std::string&,
               const std::string&,
               bool use_attach_apn,
               uint32_t tech_used,
               uint32_t iccid_len,
               uint32_t sim_type,
               uint32_t modem_state,
               int interface_index),
              (override));

  MOCK_METHOD(void,
              NotifyServiceStateChanged,
              (const Service&, Service::ConnectState),
              (override));
#if !defined(DISABLE_WIFI)
  MOCK_METHOD(void,
              Notify80211Disconnect,
              (WiFiDisconnectByWhom, IEEE_80211::WiFiReasonCode),
              (override));
#endif  // DISABLE_WIFI
  MOCK_METHOD(void, NotifyWiFiSupplicantSuccess, (int), (override));
  MOCK_METHOD(void, Notify3GPPRegistrationDelayedDropPosted, (), (override));
  MOCK_METHOD(void, Notify3GPPRegistrationDelayedDropCanceled, (), (override));
  MOCK_METHOD(void, NotifyCorruptedProfile, (), (override));
  MOCK_METHOD(bool, SendEnumToUMA, (const std::string&, int, int), (override));
  MOCK_METHOD(bool, SendBoolToUMA, (const std::string&, bool), (override));
  MOCK_METHOD(bool,
              SendToUMA,
              (const std::string&, int, int, int, int),
              (override));
  MOCK_METHOD(bool, SendSparseToUMA, (const std::string&, int), (override));
  MOCK_METHOD(void, NotifyWifiAutoConnectableServices, (int), (override));
  MOCK_METHOD(void, NotifyWifiAvailableBSSes, (int), (override));
  MOCK_METHOD(void, NotifyWifiTxBitrate, (int), (override));
  MOCK_METHOD(void,
              NotifyUserInitiatedConnectionResult,
              (const std::string&, int),
              (override));
  MOCK_METHOD(void,
              NotifyUserInitiatedConnectionFailureReason,
              (const std::string&, const Service::ConnectFailure),
              (override));
  MOCK_METHOD(void,
              NotifyDeviceConnectionStatus,
              (Metrics::ConnectionStatus),
              (override));
  MOCK_METHOD(void,
              NotifyNetworkConnectionIPType,
              (Technology, Metrics::NetworkConnectionIPType),
              (override));
  MOCK_METHOD(void,
              NotifyIPv6ConnectivityStatus,
              (Technology, bool),
              (override));
  MOCK_METHOD(void, NotifyDevicePresenceStatus, (Technology, bool), (override));
  MOCK_METHOD(void,
              NotifyUnreliableLinkSignalStrength,
              (Technology, int),
              (override));
  MOCK_METHOD(void,
              NotifyConnectionDiagnosticsIssue,
              (const std::string&),
              (override));
  MOCK_METHOD(void,
              NotifyPortalDetectionMultiProbeResult,
              (const PortalDetector::Result&),
              (override));
  MOCK_METHOD(void,
              NotifyWiFiConnectionAttempt,
              (const Metrics::WiFiConnectionAttemptInfo&),
              (override));
  MOCK_METHOD(void,
              NotifyWiFiConnectionAttemptResult,
              (NetworkServiceError),
              (override));
  MOCK_METHOD(void,
              NotifyWiFiAdapterStateChanged,
              (bool, const WiFiAdapterInfo&),
              (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_METRICS_H_
