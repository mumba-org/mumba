// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/data-snapshotd/block_ui_controller.h"
#include "arc/data-snapshotd/fake_process_launcher.h"
#include "arc/data-snapshotd/mock_esc_key_watcher.h"

namespace arc {
namespace data_snapshotd {

namespace {

constexpr int kPercent = 10;
constexpr char kSnapshotDir[] = "/snapshot/dir/";

}  // namespace

class BlockUiControllerTest : public testing::Test {
 public:
  void SetUp() override {
    process_launcher_ = std::make_unique<FakeProcessLauncher>();
  }

  void TearDown() override { process_launcher_.reset(); }

  void ExpectUiScreenShown(bool shown = true) {
    process_launcher_->ExpectUiScreenShown(base::FilePath(kSnapshotDir), shown);
  }

  void ExpectProgressUpdated(int percent, bool updated = true) {
    process_launcher_->ExpectProgressUpdated(percent, updated);
  }

  BlockUiController::LaunchProcessCallback GetLaunchProcessCallback() const {
    return process_launcher_->GetLaunchProcessCallback();
  }

  std::unique_ptr<FakeEscKeyWatcher> CreateWatcher() {
    return std::make_unique<FakeEscKeyWatcher>(&delegate_);
  }

 private:
  std::unique_ptr<FakeProcessLauncher> process_launcher_;
  MockEscKeyWatcherDelegate delegate_;
};

TEST_F(BlockUiControllerTest, ShowScreenSucces) {
  ExpectUiScreenShown();
  auto controller = BlockUiController::CreateForTesting(
      CreateWatcher(), base::FilePath(kSnapshotDir),
      GetLaunchProcessCallback());
  EXPECT_TRUE(controller->ShowScreen());
}

TEST_F(BlockUiControllerTest, ShowScreenFailure) {
  ExpectUiScreenShown(false /* shown */);

  auto controller = BlockUiController::CreateForTesting(
      CreateWatcher(), base::FilePath(kSnapshotDir),
      GetLaunchProcessCallback());
  EXPECT_FALSE(controller->ShowScreen());
}

TEST_F(BlockUiControllerTest, UpdateProgressSuccess) {
  ExpectUiScreenShown();
  auto controller = BlockUiController::CreateForTesting(
      CreateWatcher(), base::FilePath(kSnapshotDir),
      GetLaunchProcessCallback());
  EXPECT_TRUE(controller->ShowScreen());

  ExpectProgressUpdated(kPercent);
  EXPECT_TRUE(controller->UpdateProgress(kPercent));
}

TEST_F(BlockUiControllerTest, UpdateProgressNoScreenFailure) {
  ExpectUiScreenShown(false /* shown */);
  auto controller = BlockUiController::CreateForTesting(
      CreateWatcher(), base::FilePath(kSnapshotDir),
      GetLaunchProcessCallback());
  EXPECT_FALSE(controller->ShowScreen());

  ExpectUiScreenShown(false /* shown */);
  EXPECT_FALSE(controller->UpdateProgress(kPercent));
  EXPECT_FALSE(controller->shown());
}

TEST_F(BlockUiControllerTest, UpdateProgressShowScreenSuccess) {
  ExpectUiScreenShown(false /* shown */);
  auto controller = BlockUiController::CreateForTesting(
      CreateWatcher(), base::FilePath(kSnapshotDir),
      GetLaunchProcessCallback());

  EXPECT_FALSE(controller->ShowScreen());

  ExpectUiScreenShown();
  ExpectProgressUpdated(kPercent);
  EXPECT_TRUE(controller->UpdateProgress(kPercent));
  EXPECT_TRUE(controller->shown());
}

TEST_F(BlockUiControllerTest, UpdateProgressFailure) {
  ExpectUiScreenShown();
  auto controller = BlockUiController::CreateForTesting(
      CreateWatcher(), base::FilePath(kSnapshotDir),
      GetLaunchProcessCallback());
  EXPECT_TRUE(controller->ShowScreen());

  ExpectProgressUpdated(kPercent, false /* updated */);
  EXPECT_FALSE(controller->UpdateProgress(kPercent));
  EXPECT_TRUE(controller->shown());
}

}  // namespace data_snapshotd
}  // namespace arc
