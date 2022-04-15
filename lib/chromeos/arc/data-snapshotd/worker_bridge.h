// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_WORKER_BRIDGE_H_
#define ARC_DATA_SNAPSHOTD_WORKER_BRIDGE_H_

#include <memory>
#include <string>

#include <base/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_method_response.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <dbus/message.h>

namespace arc {
namespace data_snapshotd {

class UpstartClient;
class WorkerClient;

// This class is responsible for bootstrapping D-Bus communication with
// arc-data-snapshotd-worker daemon and delegating taking and loading data/
// snapshot operations to it.
class WorkerBridge {
 public:
  virtual ~WorkerBridge() = default;

  static std::unique_ptr<WorkerBridge> Create(
      const scoped_refptr<dbus::Bus>& bus);

  static std::unique_ptr<WorkerBridge> CreateForTesting(
      std::unique_ptr<UpstartClient> upstart_client,
      std::unique_ptr<WorkerClient> worker_client);
  static void SetFakeInstanceForTesting(std::unique_ptr<WorkerBridge> bridge);

  // Interval between successful connection attempts.
  static base::TimeDelta connection_attempt_interval_for_testing();

  // The maximum number of consecutive connection attempts before giving up.
  static int max_connection_attempt_count_for_testing();

  // Starts and initializes arc-data-snapshotd-worker daemon. The daemon is
  // stopped in dtor.
  // |account_id| - the MGS account ID to take/load data/ snapshot to.
  // |on_initialized| - callback to be invoked once the daemon is started and
  //                    D-Bus is available.
  virtual void Init(const std::string& account_id,
                    base::OnceCallback<void(bool)> on_initialized) = 0;

  // Wire up D-Bus calls to WorkerClient:
  virtual void TakeSnapshot(
      const std::string& account_id,
      const std::string& private_key,
      const std::string& public_key,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>>
          response) = 0;
  virtual void LoadSnapshot(
      const std::string& account_id,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
          response) = 0;

  virtual bool is_available_for_testing() const = 0;
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_WORKER_BRIDGE_H_
