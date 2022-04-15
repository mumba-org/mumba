// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/worker_client.h"

#include <utility>

#include <base/callback.h>
#include <dbus/message.h>

#include <arc/data-snapshotd/dbus-constants.h>

namespace arc {
namespace data_snapshotd {

void OnBoolMethodCallback(base::OnceCallback<void(bool)> callback,
                          dbus::Response* response) {
  if (!response) {
    std::move(callback).Run(false /* success */);
    return;
  }
  dbus::MessageReader reader(response);
  bool success;
  if (!reader.PopBool(&success)) {
    std::move(callback).Run(false /* success */);
    return;
  }
  std::move(callback).Run(success);
}

void OnDoubleBoolMethodCallback(base::OnceCallback<void(bool, bool)> callback,
                                dbus::Response* response) {
  if (!response) {
    std::move(callback).Run(false /* success */, false /* last */);
    return;
  }
  dbus::MessageReader reader(response);
  bool success;
  if (!reader.PopBool(&success)) {
    std::move(callback).Run(false /* success */, false /* last */);
    return;
  }
  bool last;
  if (!reader.PopBool(&last)) {
    std::move(callback).Run(false /* success */, false /* last */);
    return;
  }
  std::move(callback).Run(success, last);
}

WorkerClient::WorkerClient(const scoped_refptr<dbus::Bus>& bus) {
  proxy_ = bus->GetObjectProxy(
      arc::data_snapshotd::kArcDataSnapshotdWorkerServiceName,
      dbus::ObjectPath(
          arc::data_snapshotd::kArcDataSnapshotdWorkerServicePath));
}

WorkerClient::~WorkerClient() {}

void WorkerClient::WaitForServiceToBeAvailable(
    dbus::ObjectProxy::WaitForServiceToBeAvailableCallback callback) {
  proxy_->WaitForServiceToBeAvailable(std::move(callback));
}

void WorkerClient::TakeSnapshot(const std::string& account_id,
                                const std::string& private_key,
                                const std::string& public_key,
                                base::OnceCallback<void(bool)> callback) {
  dbus::MethodCall method_call(
      arc::data_snapshotd::kArcDataSnapshotdWorkerServiceInterface,
      arc::data_snapshotd::kTakeSnapshotMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(account_id);
  writer.AppendString(private_key);
  writer.AppendString(public_key);

  proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&OnBoolMethodCallback, std::move(callback)));
}

void WorkerClient::LoadSnapshot(const std::string& account_id,
                                base::OnceCallback<void(bool, bool)> callback) {
  dbus::MethodCall method_call(
      arc::data_snapshotd::kArcDataSnapshotdWorkerServiceInterface,
      arc::data_snapshotd::kLoadSnapshotMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(account_id);
  proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&OnDoubleBoolMethodCallback, std::move(callback)));
}

}  // namespace data_snapshotd
}  // namespace arc
