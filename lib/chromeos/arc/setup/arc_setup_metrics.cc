// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc_setup_metrics.h"  // NOLINT - TODO(b/32971714): fix it properly.

#include <utility>

#include <metrics/metrics_library.h>

namespace arc {

namespace {

// The string value need to be the same as in Chromiums's
// src/tools/histogram.xml
constexpr char kCodeVerificationResult[] = "Arc.CodeVerificationResult";
constexpr char kBootContinueCodeInstallationResult[] =
    "Arc.BootContinueCodeInstallationResult";
constexpr char kCodeReloationResult[] = "Arc.CodeRelocationResult";
constexpr char kCodeVerificationTime[] = "Arc.CodeVerificationTime";
constexpr char kCodeRelocationTime[] = "Arc.CodeRelocationTime";
constexpr char kCodeSigningTime[] = "Arc.CodeSigningTime";
constexpr char kCodeIntegrityCheckingTotalTime[] =
    "Arc.CodeIntegrityCheckingTotalTime";
constexpr char kSdkVersionUpgradeType[] = "Arc.SdkVersionUpgradeType";

}  // namespace

ArcSetupMetrics::ArcSetupMetrics()
    : metrics_library_(std::make_unique<MetricsLibrary>()) {}

bool ArcSetupMetrics::SendCodeVerificationResult(
    ArcCodeVerificationResult verification_result) {
  return metrics_library_->SendEnumToUMA(
      kCodeVerificationResult, static_cast<int>(verification_result),
      static_cast<int>(ArcCodeVerificationResult::COUNT));
}

bool ArcSetupMetrics::SendCodeRelocationResult(
    ArcCodeRelocationResult relocation_result) {
  return metrics_library_->SendEnumToUMA(
      kCodeReloationResult, static_cast<int>(relocation_result),
      static_cast<int>(ArcCodeRelocationResult::COUNT));
}

bool ArcSetupMetrics::SendBootContinueCodeInstallationResult(
    ArcBootContinueCodeInstallationResult verifcation_result) {
  return metrics_library_->SendEnumToUMA(
      kBootContinueCodeInstallationResult, static_cast<int>(verifcation_result),
      static_cast<int>(ArcBootContinueCodeInstallationResult::COUNT));
}

bool ArcSetupMetrics::SendCodeVerificationTime(
    base::TimeDelta verification_time) {
  return SendDurationToUMA(kCodeVerificationTime, verification_time);
}

bool ArcSetupMetrics::SendCodeRelocationTime(base::TimeDelta relocation_time) {
  return SendDurationToUMA(kCodeRelocationTime, relocation_time);
}

bool ArcSetupMetrics::SendCodeSigningTime(base::TimeDelta signing_time) {
  return SendDurationToUMA(kCodeSigningTime, signing_time);
}

bool ArcSetupMetrics::SendCodeIntegrityCheckingTotalTime(
    base::TimeDelta total_time) {
  return SendDurationToUMA(kCodeIntegrityCheckingTotalTime, total_time);
}

bool ArcSetupMetrics::SendSdkVersionUpgradeType(
    ArcSdkVersionUpgradeType upgrade_type) {
  return metrics_library_->SendEnumToUMA(
      kSdkVersionUpgradeType, static_cast<int>(upgrade_type),
      static_cast<int>(ArcSdkVersionUpgradeType::COUNT));
}

void ArcSetupMetrics::SetMetricsLibraryForTesting(
    std::unique_ptr<MetricsLibraryInterface> metrics_library) {
  metrics_library_ = std::move(metrics_library);
}

bool ArcSetupMetrics::SendDurationToUMA(const std::string& metric_name,
                                        base::TimeDelta duration) {
  constexpr int kMinDurationMs = 1;
  constexpr int kMaxDurationMs = 30000;
  constexpr int kNumDurationBuckets = 50;

  return metrics_library_->SendToUMA(
      metric_name, static_cast<int>(duration.InMillisecondsRoundedUp()),
      kMinDurationMs, kMaxDurationMs, kNumDurationBuckets);
}

}  // namespace arc
