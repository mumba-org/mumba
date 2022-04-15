// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_WORKER_CLIENT_H_
#define ARC_DATA_SNAPSHOTD_WORKER_CLIENT_H_

#include <string>

#include <base/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

namespace arc {
namespace data_snapshotd {

// This class is a client proxy to ArcDataSnapshotdWorker D-Bus daemon.
// It is responsible for writing up taking and loading snapshot operations.
class WorkerClient {
 public:
  explicit WorkerClient(const scoped_refptr<dbus::Bus>& bus);
  WorkerClient(const WorkerClient&) = delete;
  WorkerClient& operator=(const WorkerClient&) = delete;
  virtual ~WorkerClient();

  // Registers |callback| to run when the arc-data-snapshotd-worker becomes
  // available.
  // If the service is already available, or if connecting to the name-owner-
  // changed signal fails, |callback| will be run once asynchronously.
  // Otherwise, |callback| will be run once in the future after the service
  // becomes available.
  virtual void WaitForServiceToBeAvailable(
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback callback);

  // Take the ARC data/ snapshot of the current session.
  // MGS is a current active session with |account_id|.
  // Signs the snapshot with encoded |private_key| and stores |public_key| to
  // disk.
  // Note: the caller is responsible for storing |public_key| encoded SHA256
  // digest into bootlock box.
  virtual void TakeSnapshot(const std::string& account_id,
                            const std::string& private_key,
                            const std::string& public_key,
                            base::OnceCallback<void(bool)> callback);
  // Load the ARC data/ snapshot to the current active MGS with |account_id|.
  virtual void LoadSnapshot(const std::string& account_id,
                            base::OnceCallback<void(bool, bool)> callback);

 private:
  dbus::ObjectProxy* proxy_;
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_WORKER_CLIENT_H_
