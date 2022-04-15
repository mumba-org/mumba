// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc_setup_metrics.h"  // NOLINT - TODO(b/32971714): fix it properly.

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

using ::testing::_;

namespace arc {
namespace {

class ArcSetupMetricsTest : public testing::Test {
 protected:
  ArcSetupMetricsTest() {
    arc_setup_metrics_.SetMetricsLibraryForTesting(
        std::make_unique<MetricsLibraryMock>());
  }
  ArcSetupMetricsTest(const ArcSetupMetricsTest&) = delete;
  ArcSetupMetricsTest& operator=(const ArcSetupMetricsTest&) = delete;

  ~ArcSetupMetricsTest() override = default;

  MetricsLibraryMock* GetMetricsLibraryMock() {
    return static_cast<MetricsLibraryMock*>(
        arc_setup_metrics_.metrics_library_for_testing());
  }

  ArcSetupMetrics arc_setup_metrics_;
};

TEST_F(ArcSetupMetricsTest, SendCodeVerificationResult) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(_, static_cast<int>(ArcCodeVerificationResult::SUCCESS), _))
      .Times(1);
  arc_setup_metrics_.SendCodeVerificationResult(
      ArcCodeVerificationResult::SUCCESS);
}

TEST_F(ArcSetupMetricsTest, SendCodeRelocationResult) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(_, static_cast<int>(ArcCodeRelocationResult::SUCCESS), _))
      .Times(1);
  arc_setup_metrics_.SendCodeRelocationResult(ArcCodeRelocationResult::SUCCESS);
}

TEST_F(ArcSetupMetricsTest, SendBootContinueCodeInstallationResult) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          _, static_cast<int>(ArcBootContinueCodeInstallationResult::SUCCESS),
          _))
      .Times(1);
  arc_setup_metrics_.SendBootContinueCodeInstallationResult(
      ArcBootContinueCodeInstallationResult::SUCCESS);
}

TEST_F(ArcSetupMetricsTest, SendCodeVerificationTime) {
  base::TimeDelta t = base::Milliseconds(1234);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, 1234, _, _, _)).Times(1);
  arc_setup_metrics_.SendCodeVerificationTime(t);
}

TEST_F(ArcSetupMetricsTest, SendCodeRelocationTime) {
  base::TimeDelta t = base::Milliseconds(4321);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, 4321, _, _, _)).Times(1);
  arc_setup_metrics_.SendCodeRelocationTime(t);
}

TEST_F(ArcSetupMetricsTest, SendCodeSigningTime) {
  base::TimeDelta t = base::Milliseconds(3214);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, 3214, _, _, _)).Times(1);
  arc_setup_metrics_.SendCodeSigningTime(t);
}

TEST_F(ArcSetupMetricsTest, SendCodeIntegrityCheckingTotalTime) {
  base::TimeDelta t = base::Milliseconds(3333);
  EXPECT_CALL(*GetMetricsLibraryMock(), SendToUMA(_, 3333, _, _, _)).Times(1);
  arc_setup_metrics_.SendCodeIntegrityCheckingTotalTime(t);
}

TEST_F(ArcSetupMetricsTest, SendSdkVersionUpgradeType) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(_, static_cast<int>(ArcSdkVersionUpgradeType::N_TO_P), _))
      .Times(1);
  arc_setup_metrics_.SendSdkVersionUpgradeType(
      ArcSdkVersionUpgradeType::N_TO_P);
}

}  // namespace
}  // namespace arc
