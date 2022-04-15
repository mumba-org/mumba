// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_FAKE_PROCESS_LAUNCHER_H_
#define ARC_DATA_SNAPSHOTD_FAKE_PROCESS_LAUNCHER_H_

#include <queue>

#include <arc/data-snapshotd/block_ui_controller.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/process/launch.h>

namespace arc {
namespace data_snapshotd {

class FakeProcessLauncher {
 public:
  FakeProcessLauncher();
  FakeProcessLauncher(const FakeProcessLauncher&) = delete;
  FakeProcessLauncher& operator=(const FakeProcessLauncher&) = delete;
  ~FakeProcessLauncher();

  void ExpectUiScreenShown(const base::FilePath& snapshot_dir, bool result);
  void ExpectProgressUpdated(int percent, bool result);

  // The returned callback should be passed into BlockUiController ctor for
  // testing.
  BlockUiController::LaunchProcessCallback GetLaunchProcessCallback();

 private:
  struct Event {
    bool Match(const base::CommandLine& expected_cmd,
               const base::LaunchOptions& expected_options) const;

    base::CommandLine cmd;
    base::LaunchOptions options;
    bool result;
  };

  bool LaunchProcess(const base::CommandLine& cmd,
                     const base::LaunchOptions& options);

  std::queue<Event> expected_events_;
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_FAKE_PROCESS_LAUNCHER_H_
