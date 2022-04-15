// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/block_ui_controller.h"

#include <stdlib.h>

#include <utility>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/process/launch.h>
#include <base/time/time.h>
#include <brillo/process/process.h>

namespace arc {
namespace data_snapshotd {

namespace {

constexpr base::TimeDelta kTimeout = base::Seconds(20);

constexpr char kDisplayBinary[] = "chromeos-boot-alert";

// Environment variables and values:
constexpr char kMessageOptions[] = "MESSAGE_OPTIONS";
constexpr char kMarkup[] = "--markup";
constexpr char kTmpDir[] = "TMPDIR";
constexpr char kTmpDirValue[] = "/var/cache/arc-data-snapshot/tmp/";
constexpr char kImageBackgroundRgb[] = "IMAGE_BACKGROUND_RGB";
constexpr char kImageBackgroundRgbValue[] = "fefefe";
constexpr char kImageTextColor[] = "IMAGE_TEXT_COLOR";
constexpr char kImageTextColorValue[] = "Black";
constexpr char kAssetsImagePath[] = "ASSETS_IMAGE_PATH";
constexpr char kAssetsImagePathValue[] = "images";
constexpr char kProgressBarWidth[] = "PROGRESS_BAR_WIDTH";
constexpr char kProgressBarWidthValue[] = "1";
constexpr char kProgressBarRgb[] = "PROGRESS_BAR_RGB";
constexpr char kProgressBarRgbValue[] = "1A73E8";

bool LaunchProcessImpl(const base::CommandLine& cmd,
                       const base::LaunchOptions& options) {
  int exit_code;
  auto p = base::LaunchProcess(cmd, options);
  if (!p.WaitForExitWithTimeout(kTimeout, &exit_code) ||
      exit_code != EXIT_SUCCESS) {
    return false;
  }
  return true;
}

}  // namespace

base::CommandLine GetShowScreenCommandLine() {
  base::CommandLine cmd{base::FilePath(kDisplayBinary)};
  cmd.AppendArg("update_arc_data_snapshot");
  return cmd;
}

base::CommandLine GetUpdateProgressCommandLine(int percent) {
  base::CommandLine cmd{base::FilePath(kDisplayBinary)};
  cmd.AppendArg("update_progress");
  cmd.AppendArg(std::to_string(percent));
  return cmd;
}

base::LaunchOptions GetShowScreenOptions(const base::FilePath& snapshot_dir) {
  base::EnvironmentMap env;
  env[kMessageOptions] = kMarkup;
  env[kTmpDir] = kTmpDirValue;
  env[kAssetsImagePath] = snapshot_dir.Append(kAssetsImagePathValue).value();
  env[kImageBackgroundRgb] = kImageBackgroundRgbValue;
  env[kImageTextColor] = kImageTextColorValue;

  base::LaunchOptions options;
  options.environment = std::move(env);
  return options;
}

base::LaunchOptions GetUpdateProgressOptions() {
  base::EnvironmentMap env;
  env[kProgressBarWidth] = kProgressBarWidthValue;
  env[kProgressBarRgb] = kProgressBarRgbValue;
  env[kImageBackgroundRgb] = kImageBackgroundRgbValue;

  base::LaunchOptions options;
  options.environment = std::move(env);
  return options;
}

BlockUiController::BlockUiController(std::unique_ptr<EscKeyWatcher> watcher,
                                     const base::FilePath& snapshot_dir)
    : BlockUiController(std::move(watcher),
                        snapshot_dir,
                        base::BindRepeating(&LaunchProcessImpl)) {}

BlockUiController::~BlockUiController() {}

// static
std::unique_ptr<BlockUiController> BlockUiController::CreateForTesting(
    std::unique_ptr<EscKeyWatcher> watcher,
    const base::FilePath& snapshot_dir,
    LaunchProcessCallback callback) {
  return base::WrapUnique(new BlockUiController(
      std::move(watcher), snapshot_dir, std::move(callback)));
}

bool BlockUiController::ShowScreen() {
  if (shown_) {
    LOG(INFO) << "UI screen is present.";
    return true;
  }
  LOG(INFO) << "Showing UI Screen";

  // Once the screen is shown, it stays so until the daemon is stopped.
  shown_ = launch_process_callback_.Run(GetShowScreenCommandLine(),
                                        GetShowScreenOptions(snapshot_dir_));
  if (!shown_)
    LOG(ERROR) << "Failed to launch update_arc_data_snapshot screen";

  watcher_->Init();
  return shown_;
}

bool BlockUiController::UpdateProgress(int percent) {
  if (!ShowScreen()) {
    LOG(ERROR) << "Failed to start update_arc_data_snapshot_screen.";
    return false;
  }
  DCHECK(shown_);

  if (!launch_process_callback_.Run(GetUpdateProgressCommandLine(percent),
                                    GetUpdateProgressOptions())) {
    LOG(ERROR) << "Failed to update update_arc_data_snapshot";
    return false;
  }
  return true;
}

BlockUiController::BlockUiController(std::unique_ptr<EscKeyWatcher> watcher,
                                     const base::FilePath& snapshot_dir,
                                     LaunchProcessCallback callback)
    : watcher_(std::move(watcher)),
      snapshot_dir_(snapshot_dir),
      launch_process_callback_(std::move(callback)) {
  DCHECK(watcher_);
}

}  // namespace data_snapshotd
}  // namespace arc
