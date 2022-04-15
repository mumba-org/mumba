// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_UPSTART_CLIENT_H_
#define ARC_DATA_SNAPSHOTD_UPSTART_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include <base/callback_forward.h>
#include <dbus/bus.h>
#include <dbus/message.h>

namespace arc {
namespace data_snapshotd {

// This class is used to communicate with com.ubuntu.Upstart service to
// start/stop arc-data-snapshotd-worker upstart job.
class UpstartClient {
 public:
  explicit UpstartClient(const scoped_refptr<dbus::Bus>& bus);
  UpstartClient(const UpstartClient&) = delete;
  UpstartClient& operator=(const UpstartClient&) = delete;
  virtual ~UpstartClient();

  // D-Bus method call constants for testing:
  static std::string service_name_for_testing();
  static std::string job_interface_for_testing();
  static std::string worker_daemon_job_path_for_testing();
  static std::string start_method_for_testing();
  static std::string stop_method_for_testing();

  // Starts arc-data-snapshotd-worker daemon with |environment| variables.
  // |callback| is invoked with the result of the operation.
  virtual void StartWorkerDaemon(const std::vector<std::string>& environment,
                                 base::OnceCallback<void(bool)> callback);

  // Stops arc-data-snapshotd-worker daemon.
  virtual void StopWorkerDaemon();

 private:
  void CallJobMethod(const std::string& method,
                     const std::vector<std::string>& environment,
                     base::OnceCallback<void(bool)> callback);
  void OnVoidMethod(base::OnceCallback<void(bool)> callback,
                    dbus::Response* response);

  scoped_refptr<dbus::Bus> bus_;

  base::WeakPtrFactory<UpstartClient> weak_ptr_factory_{this};
};

}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_UPSTART_CLIENT_H_
