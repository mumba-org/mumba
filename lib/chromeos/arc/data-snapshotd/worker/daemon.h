// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_WORKER_DAEMON_H_
#define ARC_DATA_SNAPSHOTD_WORKER_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

#include "arc/data-snapshotd/worker/dbus_adaptor.h"

namespace arc {
namespace data_snapshotd {

// Daemon class for the arc-data-snapshotd-worker daemon.
class Daemon final : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon() override;

 private:
  // brillo::DBusServiceDaemon overrides:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  DBusAdaptor dbus_adaptor_;
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_WORKER_DAEMON_H_
