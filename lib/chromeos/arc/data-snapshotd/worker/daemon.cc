// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/worker/daemon.h"

#include <cstdlib>

#include <base/logging.h>
#include <arc/data-snapshotd/dbus-constants.h>

namespace arc {
namespace data_snapshotd {

Daemon::Daemon() : DBusServiceDaemon(kArcDataSnapshotdWorkerServiceName) {}

Daemon::~Daemon() = default;

int Daemon::OnInit() {
  LOG(INFO) << "Starting worker";
  return DBusServiceDaemon::OnInit();
}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_adaptor_.RegisterAsync(bus_, sequencer);
}

}  // namespace data_snapshotd
}  // namespace arc
