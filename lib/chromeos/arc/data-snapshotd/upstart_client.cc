// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/upstart_client.h"

#include <utility>

#include <base/callback_helpers.h>
#include <dbus/object_proxy.h>

namespace arc {
namespace data_snapshotd {

namespace {

constexpr char kUpstartServiceName[] = "com.ubuntu.Upstart";
constexpr char kUpstartJobInterface[] = "com.ubuntu.Upstart0_6.Job";
constexpr char kStartMethod[] = "Start";
constexpr char kStopMethod[] = "Stop";

// "arc_2ddata_2dsnapshotd_2dworker" below refers to the
// "arc-data-snapshotd-worker" upstart job. Upstart escapes characters that
// aren't valid in D-Bus object paths using underscore as the escape character,
// followed by the character code in hex.
constexpr char kWorkerDaemonJobPath[] =
    "/com/ubuntu/Upstart/jobs/arc_2ddata_2dsnapshotd_2dworker";

}  // namespace

UpstartClient::UpstartClient(const scoped_refptr<dbus::Bus>& bus) : bus_(bus) {}

UpstartClient::~UpstartClient() = default;

// static
std::string UpstartClient::service_name_for_testing() {
  return kUpstartServiceName;
}

// static
std::string UpstartClient::job_interface_for_testing() {
  return kUpstartJobInterface;
}

// static
std::string UpstartClient::worker_daemon_job_path_for_testing() {
  return kWorkerDaemonJobPath;
}

// static
std::string UpstartClient::start_method_for_testing() {
  return kStartMethod;
}

// static
std::string UpstartClient::stop_method_for_testing() {
  return kStopMethod;
}

void UpstartClient::StartWorkerDaemon(
    const std::vector<std::string>& environment,
    base::OnceCallback<void(bool)> callback) {
  CallJobMethod(kStartMethod, environment, std::move(callback));
}

void UpstartClient::StopWorkerDaemon() {
  CallJobMethod(kStopMethod, {} /* environment */, base::DoNothing());
}

void UpstartClient::CallJobMethod(const std::string& method,
                                  const std::vector<std::string>& environment,
                                  base::OnceCallback<void(bool)> callback) {
  dbus::ObjectProxy* job_proxy = bus_->GetObjectProxy(
      kUpstartServiceName, dbus::ObjectPath(kWorkerDaemonJobPath));
  dbus::MethodCall method_call(kUpstartJobInterface, method);
  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfStrings(environment);
  writer.AppendBool(true /* wait for response */);
  job_proxy->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&UpstartClient::OnVoidMethod,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void UpstartClient::OnVoidMethod(base::OnceCallback<void(bool)> callback,
                                 dbus::Response* response) {
  std::move(callback).Run(response);
}

}  // namespace data_snapshotd
}  // namespace arc
