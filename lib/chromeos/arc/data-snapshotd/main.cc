// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "arc/data-snapshotd/daemon.h"

int main(int argc, char** argv) {
  brillo::FlagHelper::Init(
      argc, argv,
      "arc-data-snapshotd - manages ARC++ snapshots of data/ directory.");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  return arc::data_snapshotd::Daemon().Run();
}
