// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/fake_process_launcher.h"

#include <string>

#include <base/bind.h>
#include <gtest/gtest.h>

namespace arc {
namespace data_snapshotd {

FakeProcessLauncher::FakeProcessLauncher() = default;

FakeProcessLauncher::~FakeProcessLauncher() {
  EXPECT_TRUE(expected_events_.empty());
}

void FakeProcessLauncher::ExpectUiScreenShown(
    const base::FilePath& snapshot_dir, bool result) {
  expected_events_.push(
      {GetShowScreenCommandLine(), GetShowScreenOptions(snapshot_dir), result});
}

void FakeProcessLauncher::ExpectProgressUpdated(int percent, bool result) {
  expected_events_.push({GetUpdateProgressCommandLine(percent),
                         GetUpdateProgressOptions(), result});
}

BlockUiController::LaunchProcessCallback
FakeProcessLauncher::GetLaunchProcessCallback() {
  return base::BindRepeating(&FakeProcessLauncher::LaunchProcess,
                             base::Unretained(this));
}

bool FakeProcessLauncher::Event::Match(
    const base::CommandLine& expected_cmd,
    const base::LaunchOptions& expected_options) const {
  if (cmd.GetCommandLineString() != expected_cmd.GetCommandLineString())
    return false;
  if (options.environment != expected_options.environment)
    return false;
  return true;
}

bool FakeProcessLauncher::LaunchProcess(const base::CommandLine& cmd,
                                        const base::LaunchOptions& options) {
  EXPECT_FALSE(expected_events_.empty());
  if (expected_events_.empty())
    return false;

  const auto& event = expected_events_.front();
  bool result = event.result;

  EXPECT_TRUE(event.Match(cmd, options));

  expected_events_.pop();
  return result;
}

}  // namespace data_snapshotd
}  // namespace arc
