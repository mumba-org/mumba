// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/metrics.h"

#include <iterator>
#include <memory>
#include <utility>

//#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <crypto/sha2.h>
#include <metrics/bootstat.h>
#include <metrics/structured/structured_events.h>

#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_consts.h"
#include "shill/connection_diagnostics.h"
#include "shill/logging.h"
#include "shill/wifi/wifi_endpoint.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kMetrics;
static std::string ObjectID(const Metrics* m) {
  return "(metrics)";
}
}  // namespace Logging

namespace {

constexpr char kMetricPrefix[] = "Network.Shill";

Metrics::CellularConnectResult ConvertErrorToCellularConnectResult(
    const Error::Type& error) {
  switch (error) {
    case Error::kSuccess:
      return Metrics::CellularConnectResult::kCellularConnectResultSuccess;
    case Error::kWrongState:
      return Metrics::CellularConnectResult::kCellularConnectResultWrongState;
    case Error::kOperationFailed:
      return Metrics::CellularConnectResult::
          kCellularConnectResultOperationFailed;
    case Error::kAlreadyConnected:
      return Metrics::CellularConnectResult::
          kCellularConnectResultAlreadyConnected;
    case Error::kNotRegistered:
      return Metrics::CellularConnectResult::
          kCellularConnectResultNotRegistered;
    case Error::kNotOnHomeNetwork:
      return Metrics::CellularConnectResult::
          kCellularConnectResultNotOnHomeNetwork;
    case Error::kIncorrectPin:
      return Metrics::CellularConnectResult::kCellularConnectResultIncorrectPin;
    case Error::kPinRequired:
      return Metrics::CellularConnectResult::kCellularConnectResultPinRequired;
    case Error::kPinBlocked:
      return Metrics::CellularConnectResult::kCellularConnectResultPinBlocked;
    case Error::kInvalidApn:
      return Metrics::CellularConnectResult::kCellularConnectResultInvalidApn;
    default:
      LOG(WARNING) << "Unexpected error type: " << error;
      return Metrics::CellularConnectResult::kCellularConnectResultUnknown;
  }
}

// List of WiFi adapters that have been added to AVL.
// TODO(b/229020553): Instead of hardcoding the list here and in other places
// (e.g. Tast), use a single source of truth.
static constexpr Metrics::WiFiAdapterInfo AVLWiFiAdapters[] = {
    {0x02df, 0x912d,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Marvell88w8897SDIO,
    {0x1b4b, 0x2b42,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Marvell88w8997PCIE,
    {0x168c, 0x003e,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommAtherosQCA6174,
    {0x105b, 0xe09d,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommAtherosQCA6174,
    {0x0271, 0x050a,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommAtherosQCA6174SDIO,
    {0x17cb, 0x1103,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommWCN6855,
    {0x8086, 0x08b1, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7260,
    {0x8086, 0x08b2, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7260,
    {0x8086, 0x095a, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7265,
    {0x8086, 0x095b, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7265,
    // Note that Intel 9000 is also Intel 9560 aka Jefferson Peak 2
    {0x8086, 0x9df0, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel9000,
    {0x8086, 0x31dc, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel9000,
    {0x8086, 0x2526, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel9260,
    {0x8086, 0x2723, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel22260,
    // For integrated wifi chips, use device_id and subsystem_id together
    // as an identifier.
    // 0x02f0 is for Quasar on CML; 0x4070, 0x0074, 0x6074 are for HrP2.
    {0x8086, 0x02f0, 0x0034},  // Intel9000,
    {0x8086, 0x02f0, 0x4070},  // Intel22560,
    {0x8086, 0x02f0, 0x0074},  // Intel22560,
    {0x8086, 0x02f0, 0x6074},  // Intel22560,
    {0x8086, 0x4df0, 0x0070},  // Intel22560,
    {0x8086, 0x4df0, 0x4070},  // Intel22560,
    {0x8086, 0x4df0, 0x0074},  // Intel22560,
    {0x8086, 0x4df0, 0x6074},  // Intel22560,
    {0x8086, 0xa0f0, 0x4070},  // Intel22560,
    {0x8086, 0xa0f0, 0x0074},  // Intel22560,
    {0x8086, 0xa0f0, 0x6074},  // Intel22560,
    {0x8086, 0x51f0, 0x0090},  // IntelAX211,
    {0x8086, 0x51f0, 0x0094},  // IntelAX211,
    {0x8086, 0x54f0, 0x0090},  // IntelAX211,
    {0x8086, 0x54f0, 0x0094},  // IntelAX211,
    {0x02d0, 0x4354,
     Metrics::kWiFiStructuredMetricsErrorValue},  // BroadcomBCM4354SDIO,
    {0x14e4, 0x43ec,
     Metrics::kWiFiStructuredMetricsErrorValue},  // BroadcomBCM4356PCIE,
    {0x14e4, 0x440d,
     Metrics::kWiFiStructuredMetricsErrorValue},  // BroadcomBCM4371PCIE,
    {0x10ec, 0xc822,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Realtek8822CPCIE,
    {0x10ec, 0x8852,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Realtek8852APCIE,
    {0x14c3, 0x7961,
     Metrics::kWiFiStructuredMetricsErrorValue},  // MediaTekMT7921PCIE,
    {0x037a, 0x7901,
     Metrics::kWiFiStructuredMetricsErrorValue}  // MediaTekMT7921SDIO,
};

bool CanReportAdapterInfo(const Metrics::WiFiAdapterInfo& info) {
  for (const auto& item : AVLWiFiAdapters) {
    if (item.vendor_id == info.vendor_id &&
        item.product_id == info.product_id &&
        (item.subsystem_id == info.subsystem_id ||
         item.subsystem_id == Metrics::kWiFiStructuredMetricsErrorValue))
      return true;
  }
  return false;
}
}  // namespace

Metrics::Metrics()
    : library_(&metrics_library_),
      last_default_technology_(Technology::kUnknown),
      was_last_online_(false),
      time_online_timer_(new chromeos_metrics::Timer),
      time_to_drop_timer_(new chromeos_metrics::Timer),
      time_resume_to_ready_timer_(new chromeos_metrics::Timer),
      time_suspend_actions_timer(new chromeos_metrics::Timer),
      time_(Time::GetInstance()) {
  chromeos_metrics::TimerReporter::set_metrics_lib(library_);
}

Metrics::~Metrics() = default;

// static
Metrics::WiFiChannel Metrics::WiFiFrequencyToChannel(uint16_t frequency) {
  WiFiChannel channel = kWiFiChannelUndef;
  if (kWiFiFrequency2412 <= frequency && frequency <= kWiFiFrequency2472) {
    if (((frequency - kWiFiFrequency2412) % kWiFiBandwidth5MHz) == 0)
      channel = static_cast<WiFiChannel>(kWiFiChannel2412 +
                                         (frequency - kWiFiFrequency2412) /
                                             kWiFiBandwidth5MHz);
  } else if (frequency == kWiFiFrequency2484) {
    channel = kWiFiChannel2484;
  } else if (kWiFiFrequency5170 <= frequency &&
             frequency <= kWiFiFrequency5230) {
    if ((frequency % kWiFiBandwidth20MHz) == 0)
      channel = static_cast<WiFiChannel>(kWiFiChannel5180 +
                                         (frequency - kWiFiFrequency5180) /
                                             kWiFiBandwidth20MHz);
    if ((frequency % kWiFiBandwidth20MHz) == 10)
      channel = static_cast<WiFiChannel>(kWiFiChannel5170 +
                                         (frequency - kWiFiFrequency5170) /
                                             kWiFiBandwidth20MHz);
  } else if (kWiFiFrequency5240 <= frequency &&
             frequency <= kWiFiFrequency5320) {
    if (((frequency - kWiFiFrequency5180) % kWiFiBandwidth20MHz) == 0)
      channel = static_cast<WiFiChannel>(kWiFiChannel5180 +
                                         (frequency - kWiFiFrequency5180) /
                                             kWiFiBandwidth20MHz);
  } else if (kWiFiFrequency5500 <= frequency &&
             frequency <= kWiFiFrequency5700) {
    if (((frequency - kWiFiFrequency5500) % kWiFiBandwidth20MHz) == 0)
      channel = static_cast<WiFiChannel>(kWiFiChannel5500 +
                                         (frequency - kWiFiFrequency5500) /
                                             kWiFiBandwidth20MHz);
  } else if (kWiFiFrequency5745 <= frequency &&
             frequency <= kWiFiFrequency5825) {
    if (((frequency - kWiFiFrequency5745) % kWiFiBandwidth20MHz) == 0)
      channel = static_cast<WiFiChannel>(kWiFiChannel5745 +
                                         (frequency - kWiFiFrequency5745) /
                                             kWiFiBandwidth20MHz);
  } else if (kWiFiFrequency5955 <= frequency &&
             frequency <= kWiFiFrequency7115) {
    if (((frequency - kWiFiFrequency5955) % kWiFiBandwidth20MHz) == 0)
      channel = static_cast<WiFiChannel>(kWiFiChannel5955 +
                                         (frequency - kWiFiFrequency5955) /
                                             kWiFiBandwidth20MHz);
  }
  CHECK(kWiFiChannelUndef <= channel && channel < kWiFiChannelMax);

  if (channel == kWiFiChannelUndef)
    LOG(WARNING) << "no mapping for frequency " << frequency;
  else
    SLOG(nullptr, 3) << "mapped frequency " << frequency << " to enum bucket "
                     << channel;

  return channel;
}

// static
Metrics::WiFiFrequencyRange Metrics::WiFiChannelToFrequencyRange(
    Metrics::WiFiChannel channel) {
  if (channel >= kWiFiChannelMin24 && channel <= kWiFiChannelMax24) {
    return kWiFiFrequencyRange24;
  } else if (channel >= kWiFiChannelMin5 && channel <= kWiFiChannelMax5) {
    return kWiFiFrequencyRange5;
  } else if (channel >= kWiFiChannelMin6 && channel <= kWiFiChannelMax6) {
    return kWiFiFrequencyRange6;
  } else {
    return kWiFiFrequencyRangeUndef;
  }
}

// static
Metrics::WiFiSecurity Metrics::WiFiSecurityStringToEnum(
    const std::string& security) {
  if (security == kSecurityNone) {
    return kWiFiSecurityNone;
  } else if (security == kSecurityWep) {
    return kWiFiSecurityWep;
  } else if (security == kSecurityWpa) {
    return kWiFiSecurityWpa;
  } else if (security == kSecurityRsn) {
    return kWiFiSecurityRsn;
  } else if (security == kSecurity8021x) {
    return kWiFiSecurity8021x;
  } else if (security == kSecurityPsk) {
    return kWiFiSecurityPsk;
  } else if (security == kSecurityWpa3) {
    return kWiFiSecurityWpa3;
  } else {
    return kWiFiSecurityUnknown;
  }
}

// static
Metrics::EapOuterProtocol Metrics::EapOuterProtocolStringToEnum(
    const std::string& outer) {
  if (outer == kEapMethodPEAP) {
    return kEapOuterProtocolPeap;
  } else if (outer == kEapMethodTLS) {
    return kEapOuterProtocolTls;
  } else if (outer == kEapMethodTTLS) {
    return kEapOuterProtocolTtls;
  } else if (outer == kEapMethodLEAP) {
    return kEapOuterProtocolLeap;
  } else {
    return kEapOuterProtocolUnknown;
  }
}

// static
Metrics::EapInnerProtocol Metrics::EapInnerProtocolStringToEnum(
    const std::string& inner) {
  if (inner.empty()) {
    return kEapInnerProtocolNone;
  } else if (inner == kEapPhase2AuthPEAPMD5) {
    return kEapInnerProtocolPeapMd5;
  } else if (inner == kEapPhase2AuthPEAPMSCHAPV2) {
    return kEapInnerProtocolPeapMschapv2;
  } else if (inner == kEapPhase2AuthTTLSEAPMD5) {
    return kEapInnerProtocolTtlsEapMd5;
  } else if (inner == kEapPhase2AuthTTLSEAPMSCHAPV2) {
    return kEapInnerProtocolTtlsEapMschapv2;
  } else if (inner == kEapPhase2AuthTTLSMSCHAPV2) {
    return kEapInnerProtocolTtlsMschapv2;
  } else if (inner == kEapPhase2AuthTTLSMSCHAP) {
    return kEapInnerProtocolTtlsMschap;
  } else if (inner == kEapPhase2AuthTTLSPAP) {
    return kEapInnerProtocolTtlsPap;
  } else if (inner == kEapPhase2AuthTTLSCHAP) {
    return kEapInnerProtocolTtlsChap;
  } else {
    return kEapInnerProtocolUnknown;
  }
}

// static
Metrics::PortalResult Metrics::PortalDetectionResultToEnum(
    const PortalDetector::Result& portal_result) {
  PortalResult retval = kPortalResultUnknown;
  // The only time we should end a successful portal detection is when we're
  // in the Content phase.  If we end with kStatusSuccess in any other phase,
  // then this indicates that something bad has happened.
  switch (portal_result.http_phase) {
    case PortalDetector::Phase::kDNS:
      if (portal_result.http_status == PortalDetector::Status::kFailure)
        retval = kPortalResultDNSFailure;
      else if (portal_result.http_status == PortalDetector::Status::kTimeout)
        retval = kPortalResultDNSTimeout;
      else
        LOG(DFATAL) << __func__ << ": Final result status "
                    << static_cast<int>(portal_result.http_status)
                    << " is not allowed in the DNS phase";
      break;

    case PortalDetector::Phase::kConnection:
      if (portal_result.http_status == PortalDetector::Status::kFailure)
        retval = kPortalResultConnectionFailure;
      else if (portal_result.http_status == PortalDetector::Status::kTimeout)
        retval = kPortalResultConnectionTimeout;
      else
        LOG(DFATAL) << __func__ << ": Final result status "
                    << static_cast<int>(portal_result.http_status)
                    << " is not allowed in the Connection phase";
      break;

    case PortalDetector::Phase::kHTTP:
      if (portal_result.http_status == PortalDetector::Status::kFailure)
        retval = kPortalResultHTTPFailure;
      else if (portal_result.http_status == PortalDetector::Status::kTimeout)
        retval = kPortalResultHTTPTimeout;
      else
        LOG(DFATAL) << __func__ << ": Final result status "
                    << static_cast<int>(portal_result.http_status)
                    << " is not allowed in the HTTP phase";
      break;

    case PortalDetector::Phase::kContent:
      if (portal_result.http_status == PortalDetector::Status::kSuccess)
        retval = kPortalResultSuccess;
      else if (portal_result.http_status == PortalDetector::Status::kFailure)
        retval = kPortalResultContentFailure;
      else if (portal_result.http_status == PortalDetector::Status::kRedirect)
        retval = kPortalResultContentRedirect;
      else if (portal_result.http_status == PortalDetector::Status::kTimeout)
        retval = kPortalResultContentTimeout;
      else
        LOG(DFATAL) << __func__ << ": Final result status "
                    << static_cast<int>(portal_result.http_status)
                    << " is not allowed in the Content phase";
      break;

    case PortalDetector::Phase::kUnknown:
      retval = kPortalResultUnknown;
      break;

    default:
      LOG(DFATAL) << __func__ << ": Invalid phase "
                  << static_cast<int>(portal_result.http_phase);
      break;
  }

  return retval;
}

// static
Metrics::NetworkServiceError Metrics::ConnectFailureToServiceErrorEnum(
    Service::ConnectFailure failure) {
  // Explicitly map all possible failures. So when new failures are added,
  // they will need to be mapped as well. Otherwise, the compiler will
  // complain.
  switch (failure) {
    case Service::kFailureNone:
      return kNetworkServiceErrorNone;
    case Service::kFailureAAA:
      return kNetworkServiceErrorAAA;
    case Service::kFailureActivation:
      return kNetworkServiceErrorActivation;
    case Service::kFailureBadPassphrase:
      return kNetworkServiceErrorBadPassphrase;
    case Service::kFailureBadWEPKey:
      return kNetworkServiceErrorBadWEPKey;
    case Service::kFailureConnect:
      return kNetworkServiceErrorConnect;
    case Service::kFailureDHCP:
      return kNetworkServiceErrorDHCP;
    case Service::kFailureDNSLookup:
      return kNetworkServiceErrorDNSLookup;
    case Service::kFailureEAPAuthentication:
      return kNetworkServiceErrorEAPAuthentication;
    case Service::kFailureEAPLocalTLS:
      return kNetworkServiceErrorEAPLocalTLS;
    case Service::kFailureEAPRemoteTLS:
      return kNetworkServiceErrorEAPRemoteTLS;
    case Service::kFailureHTTPGet:
      return kNetworkServiceErrorHTTPGet;
    case Service::kFailureIPsecCertAuth:
      return kNetworkServiceErrorIPsecCertAuth;
    case Service::kFailureIPsecPSKAuth:
      return kNetworkServiceErrorIPsecPSKAuth;
    case Service::kFailureInternal:
      return kNetworkServiceErrorInternal;
    case Service::kFailureNeedEVDO:
      return kNetworkServiceErrorNeedEVDO;
    case Service::kFailureNeedHomeNetwork:
      return kNetworkServiceErrorNeedHomeNetwork;
    case Service::kFailureNotAssociated:
      return kNetworkServiceErrorNotAssociated;
    case Service::kFailureNotAuthenticated:
      return kNetworkServiceErrorNotAuthenticated;
    case Service::kFailureOTASP:
      return kNetworkServiceErrorOTASP;
    case Service::kFailureOutOfRange:
      return kNetworkServiceErrorOutOfRange;
    case Service::kFailurePPPAuth:
      return kNetworkServiceErrorPPPAuth;
    case Service::kFailureSimLocked:
      return kNetworkServiceErrorSimLocked;
    case Service::kFailureNotRegistered:
      return kNetworkServiceErrorNotRegistered;
    case Service::kFailurePinMissing:
      return kNetworkServiceErrorPinMissing;
    case Service::kFailureTooManySTAs:
      return kNetworkServiceErrorTooManySTAs;
    case Service::kFailureDisconnect:
      return kNetworkServiceErrorDisconnect;
    case Service::kFailureUnknown:
    case Service::kFailureMax:
      return kNetworkServiceErrorUnknown;
  }
}

void Metrics::RegisterService(const Service& service) {
  SLOG(this, 2) << __func__;
  LOG_IF(WARNING, base::Contains(services_metrics_, &service))
      << "Repeatedly registering " << service.log_name();
  services_metrics_[&service] = std::make_unique<ServiceMetrics>();
  InitializeCommonServiceMetrics(service);
}

void Metrics::DeregisterService(const Service& service) {
  services_metrics_.erase(&service);
}

void Metrics::AddServiceStateTransitionTimer(const Service& service,
                                             const std::string& histogram_name,
                                             Service::ConnectState start_state,
                                             Service::ConnectState stop_state) {
  SLOG(this, 2) << __func__ << ": adding " << histogram_name << " for "
                << Service::ConnectStateToString(start_state) << " -> "
                << Service::ConnectStateToString(stop_state);
  ServiceMetricsLookupMap::iterator it = services_metrics_.find(&service);
  if (it == services_metrics_.end()) {
    SLOG(this, 1) << "service not found";
    DCHECK(false);
    return;
  }
  ServiceMetrics* service_metrics = it->second.get();
  CHECK(start_state < stop_state);
  auto timer = std::make_unique<chromeos_metrics::TimerReporter>(
      histogram_name, kTimerHistogramMillisecondsMin,
      kTimerHistogramMillisecondsMax, kTimerHistogramNumBuckets);
  service_metrics->start_on_state[start_state].push_back(timer.get());
  service_metrics->stop_on_state[stop_state].push_back(timer.get());
  service_metrics->timers.push_back(std::move(timer));
}

void Metrics::OnDefaultLogicalServiceChanged(
    const ServiceRefPtr& logical_service) {
  base::TimeDelta elapsed_seconds;
  Technology technology = logical_service ? logical_service->technology()
                                          : Technology(Technology::kUnknown);
  if (technology != last_default_technology_) {
    if (last_default_technology_ != Technology::kUnknown) {
      const auto histogram = GetFullMetricName(kMetricTimeOnlineSecondsSuffix,
                                               last_default_technology_);
      time_online_timer_->GetElapsedTime(&elapsed_seconds);
      SendToUMA(histogram, elapsed_seconds.InSeconds(),
                kMetricTimeOnlineSecondsMin, kMetricTimeOnlineSecondsMax,
                kTimerHistogramNumBuckets);
    }
    last_default_technology_ = technology;
    time_online_timer_->Start();
  }

  // Only consider transitions from online to offline and vice-versa; i.e.
  // ignore switching between wired and wireless or wireless and cellular.
  // TimeToDrop measures time online regardless of how we are connected.
  bool staying_online = ((logical_service != nullptr) && was_last_online_);
  bool staying_offline = ((logical_service == nullptr) && !was_last_online_);
  if (staying_online || staying_offline)
    return;

  if (logical_service == nullptr) {
    time_to_drop_timer_->GetElapsedTime(&elapsed_seconds);
    SendToUMA(kMetricTimeToDropSeconds, elapsed_seconds.InSeconds(),
              kMetricTimeToDropSecondsMin, kMetricTimeToDropSecondsMax,
              kTimerHistogramNumBuckets);
  } else {
    time_to_drop_timer_->Start();
  }

  was_last_online_ = (logical_service != nullptr);
}

void Metrics::OnDefaultPhysicalServiceChanged(const ServiceRefPtr&) {}

void Metrics::NotifyServiceStateChanged(const Service& service,
                                        Service::ConnectState new_state) {
  ServiceMetricsLookupMap::iterator it = services_metrics_.find(&service);
  if (it == services_metrics_.end()) {
    SLOG(this, 1) << "service not found";
    DCHECK(false);
    return;
  }
  ServiceMetrics* service_metrics = it->second.get();
  UpdateServiceStateTransitionMetrics(service_metrics, new_state);

  if (new_state == Service::kStateFailure)
    SendServiceFailure(service);

  bootstat::BootStat().LogEvent(
      base::StringPrintf("network-%s-%s",
                         service.technology().GetName().c_str(),
                         service.GetStateString().c_str())
          .c_str());

  if (new_state != Service::kStateConnected)
    return;

  base::TimeDelta time_resume_to_ready;
  time_resume_to_ready_timer_->GetElapsedTime(&time_resume_to_ready);
  time_resume_to_ready_timer_->Reset();
  service.SendPostReadyStateMetrics(time_resume_to_ready.InMilliseconds());
}

std::string Metrics::GetFullMetricName(const char* metric_suffix,
                                       Technology technology_id) {
  std::string technology = technology_id.GetName();
  technology[0] = base::ToUpperASCII(technology[0]);
  return base::StringPrintf("%s.%s.%s", kMetricPrefix, technology.c_str(),
                            metric_suffix);
}

void Metrics::NotifyServiceDisconnect(const Service& service) {
  Technology technology = service.technology();
  const auto histogram = GetFullMetricName(kMetricDisconnectSuffix, technology);
  SendToUMA(histogram, service.explicitly_disconnected(), kMetricDisconnectMin,
            kMetricDisconnectMax, kMetricDisconnectNumBuckets);
}

void Metrics::NotifySignalAtDisconnect(const Service& service,
                                       int16_t signal_strength) {
  // Negate signal_strength (goes from dBm to -dBm) because the metrics don't
  // seem to handle negative values well.  Now everything's positive.
  Technology technology = service.technology();
  const auto histogram =
      GetFullMetricName(kMetricSignalAtDisconnectSuffix, technology);
  SendToUMA(histogram, -signal_strength, kMetricSignalAtDisconnectMin,
            kMetricSignalAtDisconnectMax, kMetricSignalAtDisconnectNumBuckets);
}

void Metrics::NotifySuspendDone() {
  time_resume_to_ready_timer_->Start();
}

void Metrics::NotifySuspendActionsStarted() {
  if (time_suspend_actions_timer->HasStarted())
    return;
  time_suspend_actions_timer->Start();
}

void Metrics::NotifySuspendActionsCompleted(bool success) {
  if (!time_suspend_actions_timer->HasStarted())
    return;

  SuspendActionResult result =
      success ? kSuspendActionResultSuccess : kSuspendActionResultFailure;

  base::TimeDelta elapsed_time;
  time_suspend_actions_timer->GetElapsedTime(&elapsed_time);
  time_suspend_actions_timer->Reset();
  std::string time_metric, result_metric;
  time_metric = kMetricSuspendActionTimeTaken;
  result_metric = kMetricSuspendActionResult;

  SendToUMA(time_metric, elapsed_time.InMilliseconds(),
            kMetricSuspendActionTimeTakenMillisecondsMin,
            kMetricSuspendActionTimeTakenMillisecondsMax,
            kTimerHistogramNumBuckets);

  SendEnumToUMA(result_metric, result, kSuspendActionResultMax);
}

void Metrics::NotifyNeighborLinkMonitorFailure(
    Technology technology,
    IPAddress::Family family,
    patchpanel::NeighborReachabilityEventSignal::Role role) {
  const auto histogram =
      GetFullMetricName(kMetricNeighborLinkMonitorFailureSuffix, technology);
  NeighborLinkMonitorFailure failure = kNeighborLinkMonitorFailureUnknown;
  using NeighborSignal = patchpanel::NeighborReachabilityEventSignal;
  if (family == IPAddress::kFamilyIPv4) {
    switch (role) {
      case NeighborSignal::GATEWAY:
        failure = kNeighborIPv4GatewayFailure;
        break;
      case NeighborSignal::DNS_SERVER:
        failure = kNeighborIPv4DNSServerFailure;
        break;
      case NeighborSignal::GATEWAY_AND_DNS_SERVER:
        failure = kNeighborIPv4GatewayAndDNSServerFailure;
        break;
      default:
        failure = kNeighborLinkMonitorFailureUnknown;
    }
  } else if (family == IPAddress::kFamilyIPv6) {
    switch (role) {
      case NeighborSignal::GATEWAY:
        failure = kNeighborIPv6GatewayFailure;
        break;
      case NeighborSignal::DNS_SERVER:
        failure = kNeighborIPv6DNSServerFailure;
        break;
      case NeighborSignal::GATEWAY_AND_DNS_SERVER:
        failure = kNeighborIPv6GatewayAndDNSServerFailure;
        break;
      default:
        failure = kNeighborLinkMonitorFailureUnknown;
    }
  } else {
    LOG(ERROR) << __func__ << " with kFamilyUnknown";
    return;
  }

  SendEnumToUMA(histogram, failure, kNeighborLinkMonitorFailureMax);
}

void Metrics::NotifyApChannelSwitch(uint16_t frequency,
                                    uint16_t new_frequency) {
  WiFiChannel channel = WiFiFrequencyToChannel(frequency);
  WiFiChannel new_channel = WiFiFrequencyToChannel(new_frequency);
  WiFiFrequencyRange range = WiFiChannelToFrequencyRange(channel);
  WiFiFrequencyRange new_range = WiFiChannelToFrequencyRange(new_channel);
  WiFiApChannelSwitch channel_switch = kWiFiApChannelSwitchUndef;
  if (range == kWiFiFrequencyRange24 && new_range == kWiFiFrequencyRange24) {
    channel_switch = kWiFiApChannelSwitch24To24;
  } else if (range == kWiFiFrequencyRange24 &&
             new_range == kWiFiFrequencyRange5) {
    channel_switch = kWiFiApChannelSwitch24To5;
  } else if (range == kWiFiFrequencyRange5 &&
             new_range == kWiFiFrequencyRange24) {
    channel_switch = kWiFiApChannelSwitch5To24;
  } else if (range == kWiFiFrequencyRange5 &&
             new_range == kWiFiFrequencyRange5) {
    channel_switch = kWiFiApChannelSwitch5To5;
  }
  SendEnumToUMA(kMetricApChannelSwitch, channel_switch,
                kWiFiApChannelSwitchMax);
}

void Metrics::NotifyAp80211kSupport(bool neighbor_list_supported) {
  SendBoolToUMA(kMetricAp80211kSupport, neighbor_list_supported);
}

void Metrics::NotifyAp80211rSupport(bool ota_ft_supported,
                                    bool otds_ft_supported) {
  WiFiAp80211rSupport support = kWiFiAp80211rNone;
  if (otds_ft_supported) {
    support = kWiFiAp80211rOTDS;
  } else if (ota_ft_supported) {
    support = kWiFiAp80211rOTA;
  }
  SendEnumToUMA(kMetricAp80211rSupport, support, kWiFiAp80211rMax);
}

void Metrics::NotifyAp80211vDMSSupport(bool dms_supported) {
  SendBoolToUMA(kMetricAp80211vDMSSupport, dms_supported);
}

void Metrics::NotifyAp80211vBSSMaxIdlePeriodSupport(
    bool bss_max_idle_period_supported) {
  SendBoolToUMA(kMetricAp80211vBSSMaxIdlePeriodSupport,
                bss_max_idle_period_supported);
}

void Metrics::NotifyAp80211vBSSTransitionSupport(
    bool bss_transition_supported) {
  SendBoolToUMA(kMetricAp80211vBSSTransitionSupport, bss_transition_supported);
}

#if !defined(DISABLE_WIFI)
void Metrics::Notify80211Disconnect(WiFiDisconnectByWhom by_whom,
                                    IEEE_80211::WiFiReasonCode reason) {
  std::string metric_disconnect_reason;
  std::string metric_disconnect_type;
  WiFiReasonType type;

  if (by_whom == kDisconnectedByAp) {
    metric_disconnect_reason = kMetricLinkApDisconnectReason;
    metric_disconnect_type = kMetricLinkApDisconnectType;
    type = kReasonCodeTypeByAp;
  } else {
    metric_disconnect_reason = kMetricLinkClientDisconnectReason;
    metric_disconnect_type = kMetricLinkClientDisconnectType;
    switch (reason) {
      case IEEE_80211::kReasonCodeSenderHasLeft:
      case IEEE_80211::kReasonCodeDisassociatedHasLeft:
        type = kReasonCodeTypeByUser;
        break;

      case IEEE_80211::kReasonCodeInactivity:
        type = kReasonCodeTypeConsideredDead;
        break;

      default:
        type = kReasonCodeTypeByClient;
        break;
    }
  }
  SendEnumToUMA(metric_disconnect_reason, reason, IEEE_80211::kReasonCodeMax);
  SendEnumToUMA(metric_disconnect_type, type, kReasonCodeTypeMax);
}
#endif  // DISABLE_WIFI

void Metrics::NotifyWiFiSupplicantAbort() {
  SendToUMA(kMetricWifiSupplicantAttempts,
            kMetricWifiSupplicantAttemptsMax,  // abort == max
            kMetricWifiSupplicantAttemptsMin, kMetricWifiSupplicantAttemptsMax,
            kMetricWifiSupplicantAttemptsNumBuckets);
}

void Metrics::NotifyWiFiSupplicantSuccess(int attempts) {
  // Cap "success" at 1 lower than max. Max means we aborted.
  if (attempts >= kMetricWifiSupplicantAttemptsMax)
    attempts = kMetricWifiSupplicantAttemptsMax - 1;

  SendToUMA(kMetricWifiSupplicantAttempts, attempts,
            kMetricWifiSupplicantAttemptsMin, kMetricWifiSupplicantAttemptsMax,
            kMetricWifiSupplicantAttemptsNumBuckets);
}

void Metrics::RegisterDevice(int interface_index, Technology technology) {
  SLOG(this, 2) << __func__ << ": " << interface_index;

  if (technology.IsPrimaryConnectivityTechnology()) {
    bootstat::BootStat().LogEvent(
        base::StringPrintf("network-%s-registered",
                           technology.GetName().c_str())
            .c_str());
  }

  auto device_metrics = std::make_unique<DeviceMetrics>();
  device_metrics->technology = technology;
  auto histogram =
      GetFullMetricName(kMetricTimeToInitializeMillisecondsSuffix, technology);
  device_metrics->initialization_timer.reset(
      new chromeos_metrics::TimerReporter(
          histogram, kMetricTimeToInitializeMillisecondsMin,
          kMetricTimeToInitializeMillisecondsMax,
          kMetricTimeToInitializeMillisecondsNumBuckets));
  device_metrics->initialization_timer->Start();
  histogram =
      GetFullMetricName(kMetricTimeToEnableMillisecondsSuffix, technology);
  device_metrics->enable_timer.reset(new chromeos_metrics::TimerReporter(
      histogram, kMetricTimeToEnableMillisecondsMin,
      kMetricTimeToEnableMillisecondsMax,
      kMetricTimeToEnableMillisecondsNumBuckets));
  histogram =
      GetFullMetricName(kMetricTimeToDisableMillisecondsSuffix, technology);
  device_metrics->disable_timer.reset(new chromeos_metrics::TimerReporter(
      histogram, kMetricTimeToDisableMillisecondsMin,
      kMetricTimeToDisableMillisecondsMax,
      kMetricTimeToDisableMillisecondsNumBuckets));
  histogram =
      GetFullMetricName(kMetricTimeToScanMillisecondsSuffix, technology);
  device_metrics->scan_timer.reset(new chromeos_metrics::TimerReporter(
      histogram, kMetricTimeToScanMillisecondsMin,
      kMetricTimeToScanMillisecondsMax,
      kMetricTimeToScanMillisecondsNumBuckets));
  histogram =
      GetFullMetricName(kMetricTimeToConnectMillisecondsSuffix, technology);
  device_metrics->connect_timer.reset(new chromeos_metrics::TimerReporter(
      histogram, kMetricTimeToConnectMillisecondsMin,
      kMetricTimeToConnectMillisecondsMax,
      kMetricTimeToConnectMillisecondsNumBuckets));
  histogram = GetFullMetricName(kMetricTimeToScanAndConnectMillisecondsSuffix,
                                technology);
  device_metrics->scan_connect_timer.reset(new chromeos_metrics::TimerReporter(
      histogram, kMetricTimeToScanMillisecondsMin,
      kMetricTimeToScanMillisecondsMax + kMetricTimeToConnectMillisecondsMax,
      kMetricTimeToScanMillisecondsNumBuckets +
          kMetricTimeToConnectMillisecondsNumBuckets));
  devices_metrics_[interface_index] = std::move(device_metrics);
}

bool Metrics::IsDeviceRegistered(int interface_index, Technology technology) {
  SLOG(this, 2) << __func__ << ": interface index: " << interface_index
                << ", technology: " << technology;
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return false;
  // Make sure the device technologies match.
  return (technology == device_metrics->technology);
}

void Metrics::DeregisterDevice(int interface_index) {
  SLOG(this, 2) << __func__ << ": interface index: " << interface_index;
  devices_metrics_.erase(interface_index);
}

void Metrics::NotifyDeviceInitialized(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  if (!device_metrics->initialization_timer->Stop())
    return;
  device_metrics->initialization_timer->ReportMilliseconds();
}

void Metrics::NotifyDeviceEnableStarted(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  device_metrics->enable_timer->Start();
}

void Metrics::NotifyDeviceEnableFinished(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  if (!device_metrics->enable_timer->Stop())
    return;
  device_metrics->enable_timer->ReportMilliseconds();
}

void Metrics::NotifyDeviceDisableStarted(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  device_metrics->disable_timer->Start();
}

void Metrics::NotifyDeviceDisableFinished(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  if (!device_metrics->disable_timer->Stop())
    return;
  device_metrics->disable_timer->ReportMilliseconds();
}

void Metrics::NotifyDeviceScanStarted(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  device_metrics->scan_timer->Start();
  device_metrics->scan_connect_timer->Start();
}

void Metrics::NotifyDeviceScanFinished(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  if (!device_metrics->scan_timer->Stop())
    return;
  // Don't send TimeToScan metrics if the elapsed time exceeds the max metrics
  // value.  Huge scan times usually mean something's gone awry; for cellular,
  // for instance, this usually means that the modem is in an area without
  // service and we're not interested in this scenario.
  base::TimeDelta elapsed_time;
  device_metrics->scan_timer->GetElapsedTime(&elapsed_time);
  if (elapsed_time.InMilliseconds() <= kMetricTimeToScanMillisecondsMax)
    device_metrics->scan_timer->ReportMilliseconds();
}

void Metrics::ResetScanTimer(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  device_metrics->scan_timer->Reset();
}

void Metrics::NotifyDeviceConnectStarted(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  device_metrics->connect_timer->Start();
}

void Metrics::NotifyDeviceConnectFinished(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  if (!device_metrics->connect_timer->Stop())
    return;
  device_metrics->connect_timer->ReportMilliseconds();

  if (!device_metrics->scan_connect_timer->Stop())
    return;
  device_metrics->scan_connect_timer->ReportMilliseconds();
}

void Metrics::ResetConnectTimer(int interface_index) {
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
  if (device_metrics == nullptr)
    return;
  device_metrics->connect_timer->Reset();
  device_metrics->scan_connect_timer->Reset();
}

void Metrics::Notify3GPPRegistrationDelayedDropPosted() {
  SendEnumToUMA(kMetricCellular3GPPRegistrationDelayedDrop,
                kCellular3GPPRegistrationDelayedDropPosted,
                kCellular3GPPRegistrationDelayedDropMax);
}

void Metrics::Notify3GPPRegistrationDelayedDropCanceled() {
  SendEnumToUMA(kMetricCellular3GPPRegistrationDelayedDrop,
                kCellular3GPPRegistrationDelayedDropCanceled,
                kCellular3GPPRegistrationDelayedDropMax);
}

void Metrics::NotifyCellularDeviceDrop(const std::string& network_technology,
                                       uint16_t signal_strength) {
  SLOG(this, 2) << __func__ << ": " << network_technology << ", "
                << signal_strength;
  CellularDropTechnology drop_technology = kCellularDropTechnologyUnknown;
  if (network_technology == kNetworkTechnology1Xrtt) {
    drop_technology = kCellularDropTechnology1Xrtt;
  } else if (network_technology == kNetworkTechnologyEdge) {
    drop_technology = kCellularDropTechnologyEdge;
  } else if (network_technology == kNetworkTechnologyEvdo) {
    drop_technology = kCellularDropTechnologyEvdo;
  } else if (network_technology == kNetworkTechnologyGprs) {
    drop_technology = kCellularDropTechnologyGprs;
  } else if (network_technology == kNetworkTechnologyGsm) {
    drop_technology = kCellularDropTechnologyGsm;
  } else if (network_technology == kNetworkTechnologyHspa) {
    drop_technology = kCellularDropTechnologyHspa;
  } else if (network_technology == kNetworkTechnologyHspaPlus) {
    drop_technology = kCellularDropTechnologyHspaPlus;
  } else if (network_technology == kNetworkTechnologyLte) {
    drop_technology = kCellularDropTechnologyLte;
  } else if (network_technology == kNetworkTechnologyUmts) {
    drop_technology = kCellularDropTechnologyUmts;
  } else if (network_technology == kNetworkTechnology5gNr) {
    drop_technology = kCellularDropTechnology5gNr;
  }
  SendEnumToUMA(kMetricCellularDrop, drop_technology,
                kCellularDropTechnologyMax);
  SendToUMA(kMetricCellularSignalStrengthBeforeDrop, signal_strength,
            kMetricCellularSignalStrengthBeforeDropMin,
            kMetricCellularSignalStrengthBeforeDropMax,
            kMetricCellularSignalStrengthBeforeDropNumBuckets);
}

void Metrics::NotifyCellularConnectionResult(Error::Type error) {
  SLOG(this, 2) << __func__ << ": " << error;

  CellularConnectResult connect_result =
      ConvertErrorToCellularConnectResult(error);

  SendEnumToUMA(
      kMetricCellularConnectResult, static_cast<int>(connect_result),
      static_cast<int>(CellularConnectResult::kCellularConnectResultMax));
}

int64_t Metrics::HashApn(const std::string& uuid,
                         const std::string& apn_name,
                         const std::string& username,
                         const std::string& password) {
  std::string string1, string2;

  base::TrimString(uuid, " ", &string1);
  base::TrimString(apn_name, " ", &string2);
  string1 += string2;
  base::TrimString(username, " ", &string2);
  string1 += string2;
  base::TrimString(password, " ", &string2);
  string1 += string2;

  int64_t hash;
  crypto::SHA256HashString(string1, &hash, 8);
  return hash;
}

void Metrics::NotifyDetailedCellularConnectionResult(
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
    uint32_t iccid_length,
    uint32_t sim_type,
    uint32_t modem_state,
    int interface_index) {
  int64_t home, serving, detailed_error_hash;
  CellularApnSource apn_source = kCellularApnSourceUi;
  std::string apn_name;
  std::string username;
  std::string password;
  CellularRoamingState roaming =
      CellularRoamingState::kCellularRoamingStateUnknown;
  CellularConnectResult connect_result =
      ConvertErrorToCellularConnectResult(error);
  uint32_t connect_time = 0;
  uint32_t scan_connect_time = 0;
  DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);

  base::StringToInt64(home_mccmnc, &home);
  base::StringToInt64(serving_mccmnc, &serving);
  crypto::SHA256HashString(detailed_error, &detailed_error_hash, 8);

  if (roaming_state == kRoamingStateHome)
    roaming = kCellularRoamingStateHome;
  else if (roaming_state == kRoamingStateRoaming)
    roaming = kCellularRoamingStateRoaming;

  DCHECK(base::Contains(apn_info, cellular::kApnSource));
  if (base::Contains(apn_info, cellular::kApnSource)) {
    if (apn_info.at(cellular::kApnSource) == cellular::kApnSourceMoDb)
      apn_source = kCellularApnSourceMoDb;
    else if (apn_info.at(cellular::kApnSource) == cellular::kApnSourceUi)
      apn_source = kCellularApnSourceUi;
    else if (apn_info.at(cellular::kApnSource) == cellular::kApnSourceModem)
      apn_source = kCellularApnSourceModem;

    if (apn_info.at(cellular::kApnSource) == cellular::kApnSourceMoDb ||
        apn_info.at(cellular::kApnSource) == cellular::kApnSourceModem) {
      if (base::Contains(apn_info, kApnProperty))
        apn_name = apn_info.at(kApnProperty);
      if (base::Contains(apn_info, kApnUsernameProperty))
        username = apn_info.at(kApnUsernameProperty);
      if (base::Contains(apn_info, kApnPasswordProperty))
        password = apn_info.at(kApnPasswordProperty);
    }
  }

  if (device_metrics != nullptr) {
    base::TimeDelta elapsed_time;
    device_metrics->connect_timer->GetElapsedTime(&elapsed_time);
    connect_time = elapsed_time.InMilliseconds();
    device_metrics->scan_connect_timer->GetElapsedTime(&elapsed_time);
    scan_connect_time = elapsed_time.InMilliseconds();
  }

  SLOG(this, 3) << __func__ << ": error:" << error << " uuid:" << uuid
                << " apn:" << apn_name << " apn_source:" << apn_source
                << " ipv4:" << ipv4_config_method
                << " ipv6:" << ipv6_config_method
                << " home_mccmnc:" << home_mccmnc
                << " serving_mccmnc:" << serving_mccmnc
                << " roaming_state:" << roaming_state
                << " tech_used:" << tech_used
                << " iccid_length:" << iccid_length << " sim_type:" << sim_type
                << " modem_state:" << modem_state
                << " connect_time:" << connect_time
                << " scan_connect_time:" << scan_connect_time
                << " detailed_error:" << detailed_error;

  metrics::structured::events::cellular::CellularConnectionAttempt()
      .Setconnect_result(static_cast<int64_t>(connect_result))
      .Setapn_id(HashApn(uuid, apn_name, username, password))
      .Setipv4_config_method(ipv4_config_method)
      .Setipv6_config_method(ipv6_config_method)
      .Sethome_mccmnc(home)
      .Setserving_mccmnc(serving)
      .Setroaming_state(roaming)
      .Setuse_attach_apn(use_attach_apn)
      .Setapn_source(static_cast<int64_t>(apn_source))
      .Settech_used(tech_used)
      .Seticcid_length(iccid_length)
      .Setsim_type(sim_type)
      .Setmodem_state(modem_state)
      .Setconnect_time(connect_time)
      .Setscan_connect_time(scan_connect_time)
      .Setdetailed_error(detailed_error_hash)
      .Record();
}

void Metrics::NotifyCellularOutOfCredits(
    Metrics::CellularOutOfCreditsReason reason) {
  SendEnumToUMA(kMetricCellularOutOfCreditsReason, reason,
                kCellularOutOfCreditsReasonMax);
}

void Metrics::NotifyCorruptedProfile() {
  SendEnumToUMA(kMetricCorruptedProfile, kCorruptedProfile,
                kCorruptedProfileMax);
}

void Metrics::NotifyWifiAutoConnectableServices(int num_services) {
  SendToUMA(kMetricWifiAutoConnectableServices, num_services,
            kMetricWifiAutoConnectableServicesMin,
            kMetricWifiAutoConnectableServicesMax,
            kMetricWifiAutoConnectableServicesNumBuckets);
}

void Metrics::NotifyWifiAvailableBSSes(int num_bss) {
  SendToUMA(kMetricWifiAvailableBSSes, num_bss, kMetricWifiAvailableBSSesMin,
            kMetricWifiAvailableBSSesMax, kMetricWifiAvailableBSSesNumBuckets);
}

void Metrics::NotifyWifiTxBitrate(int bitrate) {
  SendToUMA(kMetricWifiTxBitrate, bitrate, kMetricWifiTxBitrateMin,
            kMetricWifiTxBitrateMax, kMetricWifiTxBitrateNumBuckets);
}

void Metrics::NotifyUserInitiatedConnectionResult(const std::string& name,
                                                  int result) {
  SendEnumToUMA(name, result, kUserInitiatedConnectionResultMax);
}

void Metrics::NotifyUserInitiatedConnectionFailureReason(
    const std::string& name, const Service::ConnectFailure failure) {
  UserInitiatedConnectionFailureReason reason;
  switch (failure) {
    case Service::kFailureNone:
      reason = kUserInitiatedConnectionFailureReasonNone;
      break;
    case Service::kFailureBadPassphrase:
      reason = kUserInitiatedConnectionFailureReasonBadPassphrase;
      break;
    case Service::kFailureBadWEPKey:
      reason = kUserInitiatedConnectionFailureReasonBadWEPKey;
      break;
    case Service::kFailureConnect:
      reason = kUserInitiatedConnectionFailureReasonConnect;
      break;
    case Service::kFailureDHCP:
      reason = kUserInitiatedConnectionFailureReasonDHCP;
      break;
    case Service::kFailureDNSLookup:
      reason = kUserInitiatedConnectionFailureReasonDNSLookup;
      break;
    case Service::kFailureEAPAuthentication:
      reason = kUserInitiatedConnectionFailureReasonEAPAuthentication;
      break;
    case Service::kFailureEAPLocalTLS:
      reason = kUserInitiatedConnectionFailureReasonEAPLocalTLS;
      break;
    case Service::kFailureEAPRemoteTLS:
      reason = kUserInitiatedConnectionFailureReasonEAPRemoteTLS;
      break;
    case Service::kFailureNotAssociated:
      reason = kUserInitiatedConnectionFailureReasonNotAssociated;
      break;
    case Service::kFailureNotAuthenticated:
      reason = kUserInitiatedConnectionFailureReasonNotAuthenticated;
      break;
    case Service::kFailureOutOfRange:
      reason = kUserInitiatedConnectionFailureReasonOutOfRange;
      break;
    case Service::kFailurePinMissing:
      reason = kUserInitiatedConnectionFailureReasonPinMissing;
      break;
    case Service::kFailureTooManySTAs:
      reason = kUserInitiatedConnectionFailureReasonTooManySTAs;
      break;
    default:
      reason = kUserInitiatedConnectionFailureReasonUnknown;
      break;
  }
  SendEnumToUMA(name, reason, kUserInitiatedConnectionFailureReasonMax);
}

void Metrics::NotifyDeviceConnectionStatus(ConnectionStatus status) {
  SendEnumToUMA(kMetricDeviceConnectionStatus, status, kConnectionStatusMax);
}

void Metrics::NotifyNetworkConnectionIPType(Technology technology_id,
                                            NetworkConnectionIPType type) {
  const auto histogram =
      GetFullMetricName(kMetricNetworkConnectionIPTypeSuffix, technology_id);
  SendEnumToUMA(histogram, type, kNetworkConnectionIPTypeMax);
}

void Metrics::NotifyIPv6ConnectivityStatus(Technology technology_id,
                                           bool status) {
  const auto histogram =
      GetFullMetricName(kMetricIPv6ConnectivityStatusSuffix, technology_id);
  IPv6ConnectivityStatus ipv6_status =
      status ? kIPv6ConnectivityStatusYes : kIPv6ConnectivityStatusNo;
  SendEnumToUMA(histogram, ipv6_status, kIPv6ConnectivityStatusMax);
}

void Metrics::NotifyDevicePresenceStatus(Technology technology_id,
                                         bool status) {
  const auto histogram =
      GetFullMetricName(kMetricDevicePresenceStatusSuffix, technology_id);
  DevicePresenceStatus presence =
      status ? kDevicePresenceStatusYes : kDevicePresenceStatusNo;
  SendEnumToUMA(histogram, presence, kDevicePresenceStatusMax);
}

void Metrics::NotifyUnreliableLinkSignalStrength(Technology technology_id,
                                                 int signal_strength) {
  const auto histogram = GetFullMetricName(
      kMetricUnreliableLinkSignalStrengthSuffix, technology_id);
  SendToUMA(histogram, signal_strength, kMetricServiceSignalStrengthMin,
            kMetricServiceSignalStrengthMax,
            kMetricServiceSignalStrengthNumBuckets);
}

bool Metrics::SendEnumToUMA(const std::string& name, int sample, int max) {
  SLOG(this, 5) << "Sending enum " << name << " with value " << sample << ".";
  return library_->SendEnumToUMA(name, sample, max);
}

bool Metrics::SendBoolToUMA(const std::string& name, bool b) {
  SLOG(this, 5) << "Sending bool " << name << " with value " << b << ".";
  return library_->SendBoolToUMA(name, b);
}

bool Metrics::SendToUMA(
    const std::string& name, int sample, int min, int max, int num_buckets) {
  SLOG(this, 5) << "Sending metric " << name << " with value " << sample << ".";
  return library_->SendToUMA(name, sample, min, max, num_buckets);
}

bool Metrics::SendSparseToUMA(const std::string& name, int sample) {
  SLOG(this, 5) << "Sending sparse metric " << name << " with value " << sample
                << ".";
  return library_->SendSparseToUMA(name, sample);
}

void Metrics::NotifyConnectionDiagnosticsIssue(const std::string& issue) {
  ConnectionDiagnosticsIssue issue_enum;
  if (issue == ConnectionDiagnostics::kIssueIPCollision) {
    issue_enum = kConnectionDiagnosticsIssueIPCollision;
  } else if (issue == ConnectionDiagnostics::kIssueRouting) {
    issue_enum = kConnectionDiagnosticsIssueRouting;
  } else if (issue == ConnectionDiagnostics::kIssueHTTPBrokenPortal) {
    issue_enum = kConnectionDiagnosticsIssueHTTPBrokenPortal;
  } else if (issue == ConnectionDiagnostics::kIssueDNSServerMisconfig) {
    issue_enum = kConnectionDiagnosticsIssueDNSServerMisconfig;
  } else if (issue == ConnectionDiagnostics::kIssueDNSServerNoResponse) {
    issue_enum = kConnectionDiagnosticsIssueDNSServerNoResponse;
  } else if (issue == ConnectionDiagnostics::kIssueNoDNSServersConfigured) {
    issue_enum = kConnectionDiagnosticsIssueNoDNSServersConfigured;
  } else if (issue == ConnectionDiagnostics::kIssueDNSServersInvalid) {
    issue_enum = kConnectionDiagnosticsIssueDNSServersInvalid;
  } else if (issue == ConnectionDiagnostics::kIssueNone) {
    issue_enum = kConnectionDiagnosticsIssueNone;
  } else if (issue == ConnectionDiagnostics::kIssueCaptivePortal) {
    issue_enum = kConnectionDiagnosticsIssueCaptivePortal;
  } else if (issue == ConnectionDiagnostics::kIssueGatewayUpstream) {
    issue_enum = kConnectionDiagnosticsIssueGatewayUpstream;
  } else if (issue == ConnectionDiagnostics::kIssueGatewayNotResponding) {
    issue_enum = kConnectionDiagnosticsIssueGatewayNotResponding;
  } else if (issue == ConnectionDiagnostics::kIssueServerNotResponding) {
    issue_enum = kConnectionDiagnosticsIssueServerNotResponding;
  } else if (issue == ConnectionDiagnostics::kIssueGatewayArpFailed) {
    issue_enum = kConnectionDiagnosticsIssueGatewayArpFailed;
  } else if (issue == ConnectionDiagnostics::kIssueServerArpFailed) {
    issue_enum = kConnectionDiagnosticsIssueServerArpFailed;
  } else if (issue == ConnectionDiagnostics::kIssueInternalError) {
    issue_enum = kConnectionDiagnosticsIssueInternalError;
  } else if (issue == ConnectionDiagnostics::kIssueGatewayNoNeighborEntry) {
    issue_enum = kConnectionDiagnosticsIssueGatewayNoNeighborEntry;
  } else if (issue == ConnectionDiagnostics::kIssueServerNoNeighborEntry) {
    issue_enum = kConnectionDiagnosticsIssueServerNoNeighborEntry;
  } else if (issue ==
             ConnectionDiagnostics::kIssueGatewayNeighborEntryNotConnected) {
    issue_enum = kConnectionDiagnosticsIssueGatewayNeighborEntryNotConnected;
  } else if (issue ==
             ConnectionDiagnostics::kIssueServerNeighborEntryNotConnected) {
    issue_enum = kConnectionDiagnosticsIssueServerNeighborEntryNotConnected;
  } else {
    LOG(ERROR) << __func__ << ": Invalid issue: " << issue;
    return;
  }

  SendEnumToUMA(kMetricConnectionDiagnosticsIssue, issue_enum,
                kConnectionDiagnosticsIssueMax);
}

void Metrics::NotifyPortalDetectionMultiProbeResult(
    const PortalDetector::Result& result) {
  // kTimeout is implicitly treated as a failure
  // kRedirect on HTTPS is unexpected and ignored
  PortalDetectionMultiProbeResult result_enum;
  if (result.https_status == PortalDetector::Status::kRedirect) {
    result_enum = kPortalDetectionMultiProbeResultUndefined;
  } else if (result.https_status != PortalDetector::Status::kSuccess &&
             result.http_status == PortalDetector::Status::kSuccess) {
    result_enum = kPortalDetectionMultiProbeResultHTTPSBlockedHTTPUnblocked;
  } else if (result.https_status != PortalDetector::Status::kSuccess &&
             result.http_status == PortalDetector::Status::kRedirect) {
    result_enum = kPortalDetectionMultiProbeResultHTTPSBlockedHTTPRedirected;
  } else if (result.https_status != PortalDetector::Status::kSuccess) {
    result_enum = kPortalDetectionMultiProbeResultHTTPSBlockedHTTPBlocked;
  } else if (result.https_status == PortalDetector::Status::kSuccess &&
             result.http_status == PortalDetector::Status::kSuccess) {
    result_enum = kPortalDetectionMultiProbeResultHTTPSUnblockedHTTPUnblocked;
  } else if (result.https_status == PortalDetector::Status::kSuccess &&
             result.http_status == PortalDetector::Status::kRedirect) {
    result_enum = kPortalDetectionMultiProbeResultHTTPSUnblockedHTTPRedirected;
  } else {
    result_enum = kPortalDetectionMultiProbeResultHTTPSUnblockedHTTPBlocked;
  }

  SendEnumToUMA(kMetricPortalDetectionMultiProbeResult, result_enum,
                kPortalDetectionMultiProbeResultMax);
}

void Metrics::NotifyHS20Support(bool hs20_supported, int hs20_version_number) {
  if (!hs20_supported) {
    SendEnumToUMA(kMetricHS20Support, kHS20Unsupported, kHS20SupportMax);
    return;
  }
  int hotspot_version = kHS20VersionInvalid;
  switch (hs20_version_number) {
    // Valid values.
    case 1:
      hotspot_version = kHS20Version1;
      break;
    case 2:
      hotspot_version = kHS20Version2;
      break;
    case 3:
      hotspot_version = kHS20Version3;
      break;
    // Invalid values.
    default:
      break;
  }
  SendEnumToUMA(kMetricHS20Support, hotspot_version, kHS20SupportMax);
}

void Metrics::NotifyMBOSupport(bool mbo_support) {
  SendBoolToUMA(kMetricMBOSupport, mbo_support);
}

void Metrics::NotifyWiFiServiceFailureAfterRekey(int seconds) {
  SendToUMA(kMetricTimeFromRekeyToFailureSeconds, seconds,
            kMetricTimeFromRekeyToFailureSecondsMin,
            kMetricTimeFromRekeyToFailureSecondsMax,
            kMetricTimeFromRekeyToFailureSecondsNumBuckets);
}

void Metrics::NotifyWiFiAdapterStateChanged(bool enabled,
                                            const WiFiAdapterInfo& info) {
  int64_t usecs;
  if (!time_ || !time_->GetMicroSecondsMonotonic(&usecs)) {
    LOG(ERROR) << "Failed to read timestamp";
    usecs = kWiFiStructuredMetricsErrorValue;
  }
  metrics::structured::events::wi_fi_chipset::WiFiChipsetInfo()
      .SetEventVersion(kWiFiStructuredMetricsVersion)
      .SetVendorId(info.vendor_id)
      .SetProductId(info.product_id)
      .SetSubsystemId(info.subsystem_id)
      .Record();

  bool adapter_supported = CanReportAdapterInfo(info);
  if (enabled) {
    // Monitor through UMA how often adapters are not in the allowlist.
    WiFiAdapterInAllowlist allowed =
        adapter_supported ? kInAVL : kNotInAllowlist;
    SendEnumToUMA(kMetricAdapterInfoAllowlisted, allowed, kAllowlistMax);
  }

  int v_id = adapter_supported ? info.vendor_id
                               : Metrics::kWiFiStructuredMetricsErrorValue;
  int p_id = adapter_supported ? info.product_id
                               : Metrics::kWiFiStructuredMetricsErrorValue;
  int s_id = adapter_supported ? info.subsystem_id
                               : Metrics::kWiFiStructuredMetricsErrorValue;
  metrics::structured::events::wi_fi::WiFiAdapterStateChanged()
      .SetBootId(GetBootId())
      .SetSystemTime(usecs)
      .SetEventVersion(kWiFiStructuredMetricsVersion)
      .SetAdapterState(enabled)
      .SetVendorId(v_id)
      .SetProductId(p_id)
      .SetSubsystemId(s_id)
      .Record();
}

// static
Metrics::WiFiConnectionAttemptInfo::ApSupportedFeatures
Metrics::ConvertEndPointFeatures(const WiFiEndpoint* ep) {
  Metrics::WiFiConnectionAttemptInfo::ApSupportedFeatures ap_features;
  if (ep) {
    ap_features.krv_info.neighbor_list_supported =
        ep->krv_support().neighbor_list_supported;
    ap_features.krv_info.ota_ft_supported = ep->krv_support().ota_ft_supported;
    ap_features.krv_info.otds_ft_supported =
        ep->krv_support().otds_ft_supported;
    ap_features.krv_info.dms_supported = ep->krv_support().dms_supported;
    ap_features.krv_info.bss_max_idle_period_supported =
        ep->krv_support().bss_max_idle_period_supported;
    ap_features.krv_info.bss_transition_supported =
        ep->krv_support().bss_transition_supported;

    ap_features.hs20_info.supported = ep->hs20_information().supported;
    ap_features.hs20_info.version = ep->hs20_information().version;

    ap_features.mbo_supported = ep->mbo_support();
  }
  return ap_features;
}

void Metrics::NotifyWiFiConnectionAttempt(
    const WiFiConnectionAttemptInfo& info) {
  int64_t usecs;
  if (!time_ || !time_->GetMicroSecondsMonotonic(&usecs)) {
    LOG(ERROR) << "Failed to read timestamp";
    usecs = kWiFiStructuredMetricsErrorValue;
  }
  metrics::structured::events::wi_fi::WiFiConnectionAttempt()
      .SetBootId(GetBootId())
      .SetSystemTime(usecs)
      .SetEventVersion(kWiFiStructuredMetricsVersion)
      .SetAttemptType(info.type)
      .SetAPPhyMode(info.mode)
      .SetAPSecurityMode(info.security)
      .SetAPSecurityEAPInnerProtocol(info.eap_inner)
      .SetAPSecurityEAPOuterProtocol(info.eap_outer)
      .SetAPChannel(info.channel)
      .SetRSSI(info.rssi)
      .SetSSID(info.ssid)
      .SetSSIDProvisioningMode(info.provisioning_mode)
      .SetSSIDHidden(info.ssid_hidden)
      .SetBSSID(info.bssid)
      .SetAPOUI(info.ap_oui)
      .SetAP_80211krv_NLSSupport(
          info.ap_features.krv_info.neighbor_list_supported)
      .SetAP_80211krv_OTA_FTSupport(info.ap_features.krv_info.ota_ft_supported)
      .SetAP_80211krv_OTDS_FTSupport(
          info.ap_features.krv_info.otds_ft_supported)
      .SetAP_80211krv_DMSSupport(info.ap_features.krv_info.dms_supported)
      .SetAP_80211krv_BSSMaxIdleSupport(
          info.ap_features.krv_info.bss_max_idle_period_supported)
      .SetAP_80211krv_BSSTMSupport(
          info.ap_features.krv_info.bss_transition_supported)
      .SetAP_HS20Support(info.ap_features.hs20_info.supported)
      .SetAP_HS20Version(info.ap_features.hs20_info.version)
      .SetAP_MBOSupport(info.ap_features.mbo_supported)
      .Record();
}

void Metrics::NotifyWiFiConnectionAttemptResult(
    NetworkServiceError result_code) {
  int64_t usecs;
  if (!time_ || !time_->GetMicroSecondsMonotonic(&usecs)) {
    LOG(ERROR) << "Failed to read timestamp";
    usecs = kWiFiStructuredMetricsErrorValue;
  }
  metrics::structured::events::wi_fi::WiFiConnectionAttemptResult()
      .SetBootId(GetBootId())
      .SetSystemTime(usecs)
      .SetEventVersion(kWiFiStructuredMetricsVersion)
      .SetResultCode(result_code)
      .Record();
}

// static
int Metrics::GetRegulatoryDomainValue(std::string country_code) {
  // Convert country code to upper case before checking validity.
  country_code = base::ToUpperASCII(country_code);

  // Check if alpha2 attribute is a valid ISO / IEC 3166 alpha2 country code.
  // "00", "99", "98" and "97" are special codes defined in
  // linux/include/net/regulatory.h.
  // According to https://www.iso.org/glossary-for-iso-3166.html, a subdivision
  // code is based on the two-letter code element from ISO 3166-1 followed by
  // a separator and up to three alphanumeric characters. ath10k uses '#' as
  // the separator, as reported in b/217761687. New separators may be added
  // if shown in reports. Currently, these country codes are valid:
  // 1. Special code: 00, 99, 98, 97
  // 2. Two-letter alpha 2 code, such as "US", "FR"
  // 3. Subdivision code, two-letter alpha 2 code + '#' + up to three
  // alphanumeric characters, such as "US#001", "JM#001", while the characters
  // after '#' are ignored

  if (country_code == "00") {
    return kRegDom00;
  } else if (country_code == "97") {
    return kRegDom97;
  } else if (country_code == "98") {
    return kRegDom98;
  } else if (country_code == "99") {
    return kRegDom99;
  } else if (country_code.length() < 2 || !std::isupper(country_code[0]) ||
             !std::isupper(country_code[1]) || country_code.length() > 6 ||
             (country_code.length() > 2 && country_code[2] != '#')) {
    return kCountryCodeInvalid;
  } else {
    // Calculate corresponding country code value for UMA histogram.
    return ((static_cast<int>(country_code[0]) - static_cast<int>('A')) * 26) +
           (static_cast<int>(country_code[1]) - static_cast<int>('A') + 2);
  }
}

void Metrics::InitializeCommonServiceMetrics(const Service& service) {
  Technology technology = service.technology();
  auto histogram =
      GetFullMetricName(kMetricTimeToConfigMillisecondsSuffix, technology);
  AddServiceStateTransitionTimer(service, histogram, Service::kStateConfiguring,
                                 Service::kStateConnected);
  histogram =
      GetFullMetricName(kMetricTimeToPortalMillisecondsSuffix, technology);
  AddServiceStateTransitionTimer(service, histogram, Service::kStateConnected,
                                 Service::kStateNoConnectivity);
  histogram = GetFullMetricName(kMetricTimeToRedirectFoundMillisecondsSuffix,
                                technology);
  AddServiceStateTransitionTimer(service, histogram, Service::kStateConnected,
                                 Service::kStateRedirectFound);
  histogram =
      GetFullMetricName(kMetricTimeToOnlineMillisecondsSuffix, technology);
  AddServiceStateTransitionTimer(service, histogram, Service::kStateConnected,
                                 Service::kStateOnline);
}

void Metrics::UpdateServiceStateTransitionMetrics(
    ServiceMetrics* service_metrics, Service::ConnectState new_state) {
  const char* state_string = Service::ConnectStateToString(new_state);
  SLOG(this, 5) << __func__ << ": new_state=" << state_string;
  TimerReportersList& start_timers = service_metrics->start_on_state[new_state];
  for (auto& start_timer : start_timers) {
    SLOG(this, 5) << "Starting timer for " << start_timer->histogram_name()
                  << " due to new state " << state_string << ".";
    start_timer->Start();
  }

  TimerReportersList& stop_timers = service_metrics->stop_on_state[new_state];
  for (auto& stop_timer : stop_timers) {
    SLOG(this, 5) << "Stopping timer for " << stop_timer->histogram_name()
                  << " due to new state " << state_string << ".";
    if (stop_timer->Stop())
      stop_timer->ReportMilliseconds();
  }
}

void Metrics::SendServiceFailure(const Service& service) {
  NetworkServiceError error =
      ConnectFailureToServiceErrorEnum(service.failure());

  const auto histogram =
      GetFullMetricName(kMetricNetworkServiceErrorSuffix, service.technology());

  // Publish technology specific connection failure metrics. This will
  // account for all the connection failures happening while connected to
  // a particular interface e.g. wifi, cellular etc.
  library_->SendEnumToUMA(histogram, error, kNetworkServiceErrorMax);
}

Metrics::DeviceMetrics* Metrics::GetDeviceMetrics(int interface_index) const {
  DeviceMetricsLookupMap::const_iterator it =
      devices_metrics_.find(interface_index);
  if (it == devices_metrics_.end()) {
    SLOG(this, 2) << __func__ << ": device " << interface_index << " not found";
    return nullptr;
  }
  return it->second.get();
}

// static
std::string Metrics::GetBootId() {
  std::string boot_id;
  if (!base::ReadFileToString(base::FilePath(Metrics::kBootIdProcPath),
                              &boot_id)) {
    LOG(ERROR) << "Failed to read boot_id";
    return std::string();
  }
  base::RemoveChars(boot_id, "-\r\n", &boot_id);
  return boot_id;
}

void Metrics::set_library(MetricsLibraryInterface* library) {
  chromeos_metrics::TimerReporter::set_metrics_lib(library);
  library_ = library;
}

}  // namespace shill
