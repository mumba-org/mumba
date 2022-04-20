// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_cqm.h"

#include <fcntl.h>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/net/netlink_message.h"
#include "shill/net/nl80211_message.h"
#include "shill/scope_logger.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
static std::string ObjectID(const WiFiCQM* w) {
  return "(wifi_cqm)";
}
}  // namespace Logging

namespace {
constexpr int16_t kTriggerFwDumpThresholdDbm = -80;
// Have a large enough time interval to rate limit the number of
// triggered FW dumps from shill.
constexpr auto kFwDumpCoolDownPeriod = base::Seconds(360);
constexpr char kFwDumpIntelSysFs[] =
    "/sys/kernel/debug/ieee80211/phy0/iwlwifi/iwlmvm/fw_dbg_collect";

bool WriteToFwDumpSysPath(const base::FilePath& path) {
  base::ScopedFD fd(HANDLE_EINTR(open(path.value().c_str(), O_WRONLY)));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open sysfs file"
               << ", " << path.value();
    return false;
  }

  if (!base::WriteFileDescriptor(fd.get(), "1")) {
    LOG(ERROR) << "failed to write to sys fs FW dump file";
    return false;
  }

  return true;
}

// Currently it supports Intel and this will support other chipsets once
// they are enabled.
void SetUpFwDumpPath(base::FilePath* path) {
  if (base::PathExists(base::FilePath(kFwDumpIntelSysFs))) {
    *path = base::FilePath(kFwDumpIntelSysFs);
    return;
  }

  // Path existence check for new chipsets goes here.
}

}  // namespace

// CQM thresholds for RSSI notification and Packet loss is configurable
// in kernel; Currently default kernel CQM thresholds are used.
// TODO(b/197597374) : Feature to configure CQM thresholds.
WiFiCQM::WiFiCQM(Metrics* metrics, WiFi* wifi)
    : wifi_(wifi), metrics_(metrics) {
  CHECK(wifi_) << "Passed wifi object was found null.";
  CHECK(metrics_) << "Passed metrics object was found null.";
  SetUpFwDumpPath(&fw_dump_path_);
  if (fw_dump_path_.empty()) {
    SLOG(this, 3) << "Firmware dump not supported.";
  }
}

WiFiCQM::~WiFiCQM() = default;

void WiFiCQM::TriggerFwDump() {
  if (fw_dump_path_.empty()) {
    SLOG(this, 3) << "FW dump is not supported, cannot trigger FW dump.";
    return;
  }

  auto current = base::Time::NowFromSystemTime();

  if (current < (previous_fw_dump_time_ + kFwDumpCoolDownPeriod) &&
      fw_dump_count_) {
    auto time_left = previous_fw_dump_time_ + kFwDumpCoolDownPeriod - current;
    SLOG(this, 3) << "In FW dump cool down period, no FW dump triggered, "
                  << "Time left (in sec): " << time_left.InSecondsF() << " "
                  << "Cool down period (in sec): "
                  << kFwDumpCoolDownPeriod.InSecondsF();
    return;
  }

  fw_dump_count_++;

  SLOG(this, 3) << "Triggering FW dump.";
  if (WriteToFwDumpSysPath(fw_dump_path_)) {
    SLOG(this, 3) << "FW dump trigger succeeded.";
  }

  previous_fw_dump_time_ = current;
}

void WiFiCQM::OnCQMNotify(const Nl80211Message& nl80211_message) {
  if (nl80211_message.command() != NotifyCqmMessage::kCommand) {
    LOG(ERROR) << __func__
               << ": unexpected command: " << nl80211_message.command_string();
    return;
  }

  AttributeListConstRefPtr cqm_attrs;
  if (!nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_CQM, &cqm_attrs)) {
    LOG(ERROR) << "Could not find NL80211_ATTR_CQM tag.";
    return;
  }

  // Return after RSSI message is processed. The CQM in kernel is designed to
  // publish one notification type in a given CQM message.
  uint32_t trigger_state;
  if (cqm_attrs->GetU32AttributeValue(NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT,
                                      &trigger_state)) {
    SLOG(this, 3) << "CQM NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT event found.";
    return;
  }

  // NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT can be used to determine transition
  // to RSSI high or RSSI low conditions. When feature to configure kernel CQM
  // thresholds from Shill is completed, we can use transition to RSSI high and
  // RSSI low conditions to process Beacon/Packet losses.
  // TODO(b/197597374) : Feature to configure CQM thresholds.
  if (wifi_ &&
      wifi_->GetSignalLevelForActiveService() < kTriggerFwDumpThresholdDbm) {
    SLOG(this, 3) << "CQM notification for signal strength less than "
                  << kTriggerFwDumpThresholdDbm << " dBm, Ignore.";
    return;
  }

  uint32_t packet_loss;
  if (cqm_attrs->GetU32AttributeValue(NL80211_ATTR_CQM_PKT_LOSS_EVENT,
                                      &packet_loss)) {
    SLOG(this, 3) << "CQM Packet loss event received, total packet losses: "
                  << packet_loss;
    metrics_->SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                            Metrics::kWiFiCQMPacketLoss, Metrics::kWiFiCQMMax);
    TriggerFwDump();
    return;
  }

  bool beacon_flag;
  if (cqm_attrs->GetFlagAttributeValue(NL80211_ATTR_CQM_BEACON_LOSS_EVENT,
                                       &beacon_flag)) {
    SLOG(this, 3) << "CQM notification for Beacon loss observed.";
    metrics_->SendEnumToUMA(Metrics::kMetricWiFiCQMNotification,
                            Metrics::kWiFiCQMBeaconLoss, Metrics::kWiFiCQMMax);
    TriggerFwDump();
    return;
  }
}

}  // namespace shill
