// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/worker_bridge.h"

#include <utility>

#include <arc/data-snapshotd/upstart_client.h>
#include <arc/data-snapshotd/worker_client.h>
#include <base/logging.h>
#include <base/threading/thread_task_runner_handle.h>

namespace arc {
namespace data_snapshotd {

namespace {

// Interval between successful connection attempts.
constexpr base::TimeDelta kConnectionAttemptInterval = base::Seconds(1);

// The maximum number of consecutive connection attempts before giving up.
constexpr int kMaxConnectionAttemptCount = 5;

// Fake instance of WorkerBridge for testing.
// Set by SetFakeInstanceForTesting.
std::unique_ptr<WorkerBridge> gfake_instance = nullptr;

// Implementation of WorkerBridge to be used in prod.
class WorkerBridgeImpl : public WorkerBridge {
 public:
  explicit WorkerBridgeImpl(const scoped_refptr<dbus::Bus>& bus);
  WorkerBridgeImpl(std::unique_ptr<UpstartClient> upstart_client,
                   std::unique_ptr<WorkerClient> worker_client);

  explicit WorkerBridgeImpl(const WorkerBridge&) = delete;
  WorkerBridgeImpl& operator=(const WorkerBridgeImpl&) = delete;
  ~WorkerBridgeImpl() override;

  // WorkerBridge overrides:
  void Init(const std::string& account_id,
            base::OnceCallback<void(bool)> on_initialized) override;
  void TakeSnapshot(
      const std::string& account_id,
      const std::string& private_key,
      const std::string& public_key,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response)
      override;
  void LoadSnapshot(
      const std::string& account_id,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
          response) override;

  bool is_available_for_testing() const override { return is_available_; }

 private:
  void OnWorkerDaemonStarted(bool success);
  void WaitForDBusService();
  void OnServiceAvailable(bool available);
  void ScheduleWaitingForDBusService();

  void OnSnapshotTaken(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
      bool result);
  void OnSnapshotLoaded(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
          response,
      bool result,
      bool last);

  base::OnceCallback<void(bool)> on_bridge_available_callback_;
  std::unique_ptr<UpstartClient> upstart_client_;
  std::unique_ptr<WorkerClient> worker_client_;
  int connection_attempt_ = 0;
  bool is_available_ = false;

  base::WeakPtrFactory<WorkerBridgeImpl> weak_ptr_factory_{this};
};

}  // namespace

// static
std::unique_ptr<WorkerBridge> WorkerBridge::Create(
    const scoped_refptr<dbus::Bus>& bus) {
  if (gfake_instance)
    return std::move(gfake_instance);
  else
    return std::make_unique<WorkerBridgeImpl>(bus);
}

// static
std::unique_ptr<WorkerBridge> WorkerBridge::CreateForTesting(
    std::unique_ptr<UpstartClient> upstart_client,
    std::unique_ptr<WorkerClient> worker_client) {
  return std::make_unique<WorkerBridgeImpl>(std::move(upstart_client),
                                            std::move(worker_client));
}

// static
void WorkerBridge::SetFakeInstanceForTesting(
    std::unique_ptr<WorkerBridge> fake_instance) {
  gfake_instance = std::move(fake_instance);
}

// static
base::TimeDelta WorkerBridge::connection_attempt_interval_for_testing() {
  return kConnectionAttemptInterval;
}

// static
int WorkerBridge::max_connection_attempt_count_for_testing() {
  return kMaxConnectionAttemptCount;
}

WorkerBridgeImpl::WorkerBridgeImpl(const scoped_refptr<dbus::Bus>& bus)
    : WorkerBridgeImpl(std::make_unique<UpstartClient>(bus),
                       std::make_unique<WorkerClient>(bus)) {}

WorkerBridgeImpl::WorkerBridgeImpl(
    std::unique_ptr<UpstartClient> upstart_client,
    std::unique_ptr<WorkerClient> worker_client)
    : upstart_client_(std::move(upstart_client)),
      worker_client_(std::move(worker_client)) {}

WorkerBridgeImpl::~WorkerBridgeImpl() {
  upstart_client_->StopWorkerDaemon();
}

void WorkerBridgeImpl::Init(const std::string& account_id,
                            base::OnceCallback<void(bool)> on_initialized) {
  on_bridge_available_callback_ = std::move(on_initialized);
  upstart_client_->StartWorkerDaemon(
      {"CHROMEOS_USER=" + account_id},
      base::BindOnce(&WorkerBridgeImpl::OnWorkerDaemonStarted,
                     weak_ptr_factory_.GetWeakPtr()));
}

void WorkerBridgeImpl::TakeSnapshot(
    const std::string& account_id,
    const std::string& private_key,
    const std::string& public_key,
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response) {
  if (!is_available_) {
    LOG(ERROR) << "D-Bus service is unavailable.";
    response->Return(false);
    return;
  }

  worker_client_->TakeSnapshot(
      account_id, private_key, public_key,
      base::BindOnce(&WorkerBridgeImpl::OnSnapshotTaken,
                     weak_ptr_factory_.GetWeakPtr(), std::move(response)));
}

void WorkerBridgeImpl::LoadSnapshot(
    const std::string& account_id,
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
        response) {
  if (!is_available_) {
    LOG(ERROR) << "D-Bus service is unavailable.";
    response->Return(false /* success */, false /* last */);
    return;
  }

  worker_client_->LoadSnapshot(
      account_id,
      base::BindOnce(&WorkerBridgeImpl::OnSnapshotLoaded,
                     weak_ptr_factory_.GetWeakPtr(), std::move(response)));
}

void WorkerBridgeImpl::OnWorkerDaemonStarted(bool success) {
  if (!success)
    LOG(ERROR) << "Failed to start arc-data-snapshotd-worker.";
  WaitForDBusService();
}

void WorkerBridgeImpl::WaitForDBusService() {
  if (connection_attempt_ >= kMaxConnectionAttemptCount) {
    LOG(WARNING)
        << "Stopping attempts to connect to arc-data-snapshotd-worker - "
           "too many unsuccessful attempts in a row";
    std::move(on_bridge_available_callback_).Run(false);
    return;
  }
  ++connection_attempt_;

  weak_ptr_factory_.InvalidateWeakPtrs();

  worker_client_->WaitForServiceToBeAvailable(base::BindOnce(
      &WorkerBridgeImpl::OnServiceAvailable, weak_ptr_factory_.GetWeakPtr()));
  ScheduleWaitingForDBusService();
}

void WorkerBridgeImpl::OnServiceAvailable(bool available) {
  if (!available) {
    LOG(ERROR) << "D-Bus service is unavailable.";
    return;
  }
  weak_ptr_factory_.InvalidateWeakPtrs();
  is_available_ = true;
  std::move(on_bridge_available_callback_).Run(true /* success */);
}

void WorkerBridgeImpl::ScheduleWaitingForDBusService() {
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&WorkerBridgeImpl::WaitForDBusService,
                     weak_ptr_factory_.GetWeakPtr()),
      kConnectionAttemptInterval);
}

void WorkerBridgeImpl::OnSnapshotTaken(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
    bool result) {
  response->Return(result);
}

void WorkerBridgeImpl::OnSnapshotLoaded(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
        response,
    bool result,
    bool last) {
  response->Return(result, last);
}

}  // namespace data_snapshotd
}  // namespace arc
