// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/strings/strcat.h>
#include <base/test/task_environment.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <dbus/bus.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/data-snapshotd/upstart_client.h"
#include "arc/data-snapshotd/worker_bridge.h"
#include "arc/data-snapshotd/worker_client.h"

namespace arc {
namespace data_snapshotd {

namespace {

constexpr char kFakeAccountID[] = "fake@account.id";
constexpr char kFakePrivateKey[] = "fake-private-key";
constexpr char kFakePublicKey[] = "fake-public-key";

}  // namespace

// Fake implementation of UpstartClient.
class FakeUpstartClient : public UpstartClient {
 public:
  explicit FakeUpstartClient(const scoped_refptr<dbus::Bus>& bus)
      : UpstartClient(bus) {}

  void StartWorkerDaemon(const std::vector<std::string>& environment,
                         base::OnceCallback<void(bool)> callback) override {
    if (should_start_)
      is_started_ = true;
    EXPECT_EQ(environment, environment_);
    std::move(callback).Run(should_start_);
  }

  void StopWorkerDaemon() override { is_started_ = false; }

  bool is_started() const { return is_started_; }
  void set_should_start(bool should_start) { should_start_ = should_start; }
  void set_environment(const std::vector<std::string>& environment) {
    environment_ = environment;
  }

 private:
  bool is_started_ = false;
  bool should_start_ = false;
  std::vector<std::string> environment_;
};

// Fake implementation of WorkerClient.
class FakeWorkerClient : public WorkerClient {
 public:
  explicit FakeWorkerClient(const scoped_refptr<dbus::Bus>& bus)
      : WorkerClient(bus) {}

  void WaitForServiceToBeAvailable(
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback callback)
      override {
    std::move(callback).Run(service_is_available_);
  }
  void TakeSnapshot(const std::string& account_id,
                    const std::string& private_key,
                    const std::string& public_key,
                    base::OnceCallback<void(bool)> callback) override {
    EXPECT_EQ(account_id, kFakeAccountID);
    EXPECT_EQ(private_key, kFakePrivateKey);
    EXPECT_EQ(public_key, kFakePublicKey);
    std::move(callback).Run(result_);
  }

  void LoadSnapshot(const std::string& account_id,
                    base::OnceCallback<void(bool, bool)> callback) override {
    EXPECT_EQ(account_id, kFakeAccountID);
    std::move(callback).Run(result_, last_);
  }

  void set_available(bool available) { service_is_available_ = available; }
  void set_result(bool result) { result_ = result; }
  void set_last(bool last) { last_ = last; }

 private:
  bool service_is_available_ = false;
  bool result_ = false;
  bool last_ = false;
};

class WorkerBridgeTest : public testing::Test {
 public:
  WorkerBridgeTest() : bus_(new dbus::Bus{dbus::Bus::Options{}}) {}

  void SetUp() override {
    auto upstart_client = std::make_unique<FakeUpstartClient>(bus_);
    upstart_client_ = upstart_client.get();
    upstart_client_->set_should_start(true);
    upstart_client_->set_environment(
        {base::StrCat({"CHROMEOS_USER=", kFakeAccountID})});

    auto worker_client = std::make_unique<FakeWorkerClient>(bus_);
    worker_client_ = worker_client.get();
    worker_bridge_ = WorkerBridge::CreateForTesting(std::move(upstart_client),
                                                    std::move(worker_client));
  }

  void TearDown() override { worker_bridge_.reset(); }

  void FastForwardAttempt() {
    task_environment_.FastForwardBy(
        WorkerBridge::connection_attempt_interval_for_testing());
    task_environment_.RunUntilIdle();
  }

  void RunAll(bool expected_result) {
    worker_client()->set_result(expected_result);
    RunTakeSnapshot(expected_result);
    RunLoadSnapshot(expected_result, expected_result);
  }

  void RunTakeSnapshot(bool expected_result) {
    std::unique_ptr<brillo::dbus_utils::MockDBusMethodResponse<bool>> response(
        new brillo::dbus_utils::MockDBusMethodResponse<bool>(nullptr));
    response->set_return_callback(base::Bind(
        [](bool expected_result, const bool& success) {
          EXPECT_EQ(expected_result, success);
        },
        expected_result));
    worker_bridge_->TakeSnapshot(kFakeAccountID, kFakePrivateKey,
                                 kFakePublicKey, std::move(response));
  }

  void RunLoadSnapshot(bool expected_result, bool expected_last) {
    worker_client()->set_last(expected_last);

    std::unique_ptr<brillo::dbus_utils::MockDBusMethodResponse<bool, bool>>
        response(new brillo::dbus_utils::MockDBusMethodResponse<bool, bool>(
            nullptr));
    response->set_return_callback(base::Bind(
        [](bool expected_result, bool expected_last, const bool& success,
           const bool& last) {
          EXPECT_EQ(expected_result, success);
          EXPECT_EQ(expected_last, last);
        },
        expected_result, expected_last));
    worker_bridge_->LoadSnapshot(kFakeAccountID, std::move(response));
  }

  WorkerBridge* worker_bridge() { return worker_bridge_.get(); }
  FakeWorkerClient* worker_client() { return worker_client_; }
  FakeUpstartClient* upstart_client() { return upstart_client_; }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

 private:
  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<WorkerBridge> worker_bridge_;
  FakeUpstartClient* upstart_client_;
  FakeWorkerClient* worker_client_;
};

// Test basic scenario: D-Bus service is available immediately.
TEST_F(WorkerBridgeTest, ServiceAvailable) {
  worker_client()->set_available(true);
  worker_bridge()->Init(kFakeAccountID, base::DoNothing());
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(worker_bridge()->is_available_for_testing());
  RunAll(true /* expected_result */);
}

// Test basic scenario: D-Bus service is not available.
TEST_F(WorkerBridgeTest, ServiceUnavailable) {
  worker_client()->set_available(false);
  worker_bridge()->Init(kFakeAccountID, base::DoNothing());

  task_environment_.RunUntilIdle();

  EXPECT_FALSE(worker_bridge()->is_available_for_testing());
  RunAll(false /* expected_result */);
}

// Test that service is available from the max attempt.
TEST_F(WorkerBridgeTest, ServiceAvailableMaxAttempt) {
  worker_client()->set_available(false);
  worker_bridge()->Init(kFakeAccountID, base::DoNothing());

  // Not available from the first attempt.
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(worker_bridge()->is_available_for_testing());

  size_t attempts_number =
      WorkerBridge::max_connection_attempt_count_for_testing() - 1;
  for (size_t i = 1; i < attempts_number; i++) {
    // Not available from the next max - 2 attempts.
    FastForwardAttempt();
    EXPECT_FALSE(worker_bridge()->is_available_for_testing());
  }
  // Available from the max attempt.
  worker_client()->set_available(true /* is_available */);
  FastForwardAttempt();
  EXPECT_TRUE(worker_bridge()->is_available_for_testing());
  RunAll(true /* expected_result */);
}

// Test that service is available from the max + 1 attempt and is not picked up.
TEST_F(WorkerBridgeTest, ServiceUnavailableMaxAttempts) {
  worker_client()->set_available(false);
  worker_bridge()->Init(kFakeAccountID, base::DoNothing());

  // Not available from the first attempt.
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(worker_bridge()->is_available_for_testing());

  size_t attempts_number =
      WorkerBridge::max_connection_attempt_count_for_testing();
  for (size_t i = 1; i < attempts_number; i++) {
    // Not available from the next max - 1 attempts.
    FastForwardAttempt();
    EXPECT_FALSE(worker_bridge()->is_available_for_testing());
  }
  // Available from the max + 1 attempt, but bridge is not listening.
  worker_client()->set_available(true);
  FastForwardAttempt();
  EXPECT_FALSE(worker_bridge()->is_available_for_testing());
  RunAll(false /* expected_result */);
}

}  // namespace data_snapshotd
}  // namespace arc
