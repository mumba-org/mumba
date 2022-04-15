// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Constants for the D-Bus API exposed by the arc-data-snapshotd-worker daemon.
// Normally the consumer of this API is the arc-data-snapshotd daemon.

#ifndef ARC_DATA_SNAPSHOTD_DBUS_CONSTANTS_H_
#define ARC_DATA_SNAPSHOTD_DBUS_CONSTANTS_H_

namespace arc {
namespace data_snapshotd {

constexpr char kArcDataSnapshotdWorkerServiceInterface[] =
    "org.chromium.ArcDataSnapshotdWorker";
constexpr char kArcDataSnapshotdWorkerServicePath[] =
    "/org/chromium/ArcDataSnapshotdWorker";
constexpr char kArcDataSnapshotdWorkerServiceName[] =
    "org.chromium.ArcDataSnapshotdWorker";

// Methods:
constexpr char kTakeSnapshotMethod[] = "TakeSnapshot";
constexpr char kLoadSnapshotMethod[] = "LoadSnapshot";

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_DBUS_CONSTANTS_H_
