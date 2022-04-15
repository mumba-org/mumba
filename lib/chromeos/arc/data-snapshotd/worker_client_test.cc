// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/test/task_environment.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <arc/data-snapshotd/dbus-constants.h>
#include "arc/data-snapshotd/worker_client.h"

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::WithArgs;

namespace arc {
namespace data_snapshotd {

namespace {

constexpr char kFakeAccountID[] = "fake@account.id";
constexpr char kFakePrivateKey[] = "fake-private-key";
constexpr char kFakePublicKey[] = "fake-public-key";

}  // namespace

class WorkerClientTest : public testing::TestWithParam<bool> {
 public:
  WorkerClientTest() : bus_(new dbus::MockBus{dbus::Bus::Options{}}) {
    object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), kArcDataSnapshotdWorkerServiceName,
        dbus::ObjectPath(kArcDataSnapshotdWorkerServicePath));
  }

  void SetUp() override {
    EXPECT_CALL(
        *bus_,
        GetObjectProxy(kArcDataSnapshotdWorkerServiceName,
                       dbus::ObjectPath(kArcDataSnapshotdWorkerServicePath)))
        .WillRepeatedly(Return(object_proxy_.get()));
    worker_client_ = std::make_unique<WorkerClient>(bus_);
  }

  void TearDown() override { worker_client_.reset(); }

  void ExpectWaitForServiceToBeAvailable(bool result) {
    EXPECT_CALL(*object_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillOnce(WithArgs<0>(
            Invoke([result](base::OnceCallback<void(bool)>* callback) {
              std::move(*callback).Run(result);
            })));
  }

  void ExpectTakeSnapshot(const std::string& expected_account_id,
                          const std::string& expected_private_key,
                          const std::string& expected_public_key,
                          dbus::Response* response) {
    EXPECT_CALL(*object_proxy_, DoCallMethod(_, _, _))
        .WillOnce(WithArgs<0, 2>(Invoke(
            [expected_account_id, expected_private_key, expected_public_key,
             response](dbus::MethodCall* call,
                       base::OnceCallback<void(dbus::Response*)>* callback) {
              EXPECT_EQ(call->GetInterface(),
                        kArcDataSnapshotdWorkerServiceInterface);
              EXPECT_EQ(call->GetMember(), kTakeSnapshotMethod);
              dbus::MessageReader reader(call);
              std::string account_id;
              ASSERT_TRUE(reader.PopString(&account_id));
              EXPECT_EQ(account_id, expected_account_id);

              std::string private_key;
              ASSERT_TRUE(reader.PopString(&private_key));
              EXPECT_EQ(private_key, expected_private_key);

              std::string public_key;
              ASSERT_TRUE(reader.PopString(&public_key));
              EXPECT_EQ(public_key, expected_public_key);
              std::move(*callback).Run(response);
            })));
  }

  void ExpectLoadSnapshot(const std::string& expected_account_id,
                          dbus::Response* response) {
    EXPECT_CALL(*object_proxy_, DoCallMethod(_, _, _))
        .WillOnce(WithArgs<0, 2>(
            Invoke([expected_account_id, response](
                       dbus::MethodCall* call,
                       base::OnceCallback<void(dbus::Response*)>* callback) {
              EXPECT_EQ(call->GetInterface(),
                        kArcDataSnapshotdWorkerServiceInterface);
              EXPECT_EQ(call->GetMember(), kLoadSnapshotMethod);
              dbus::MessageReader reader(call);
              std::string account_id;
              ASSERT_TRUE(reader.PopString(&account_id));
              EXPECT_EQ(account_id, expected_account_id);

              std::move(*callback).Run(response);
            })));
  }

  bool result() const { return GetParam(); }
  WorkerClient* worker_client() { return worker_client_.get(); }

 private:
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> object_proxy_;
  std::unique_ptr<WorkerClient> worker_client_;
  std::unique_ptr<dbus::Response> response_;
};

TEST_P(WorkerClientTest, WaitForServiceToBeAvailable) {
  ExpectWaitForServiceToBeAvailable(result());
  worker_client()->WaitForServiceToBeAvailable(
      base::Bind([](bool expected_result,
                    bool success) { EXPECT_EQ(expected_result, success); },
                 result()));
}

TEST_F(WorkerClientTest, TakeSnapshotEmptyResponse) {
  ExpectTakeSnapshot(kFakeAccountID, kFakePrivateKey, kFakePublicKey, nullptr);
  worker_client()->TakeSnapshot(
      kFakeAccountID, kFakePrivateKey, kFakePublicKey,
      base::Bind([](bool success) { EXPECT_FALSE(success); }));
}

TEST_P(WorkerClientTest, TakeSnapshot) {
  auto response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  writer.AppendBool(result());

  ExpectTakeSnapshot(kFakeAccountID, kFakePrivateKey, kFakePublicKey,
                     response.get());
  worker_client()->TakeSnapshot(
      kFakeAccountID, kFakePrivateKey, kFakePublicKey,
      base::Bind([](bool expected_result,
                    bool success) { EXPECT_EQ(expected_result, success); },
                 result()));
}

TEST_F(WorkerClientTest, LoadSnapshotEmptyResponse) {
  ExpectLoadSnapshot(kFakeAccountID, nullptr);
  worker_client()->LoadSnapshot(
      kFakeAccountID,
      base::Bind([](bool success, bool last) { EXPECT_FALSE(success); }));
}

TEST_F(WorkerClientTest, LoadSnapshotIncompleteFailure) {
  auto response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());

  ExpectLoadSnapshot(kFakeAccountID, response.get());
  worker_client()->LoadSnapshot(kFakeAccountID,
                                base::Bind([](bool success, bool last) {
                                  EXPECT_FALSE(success);
                                  EXPECT_FALSE(last);
                                }));

  writer.AppendBool(true /* success */);
  ExpectLoadSnapshot(kFakeAccountID, response.get());
  worker_client()->LoadSnapshot(kFakeAccountID,
                                base::Bind([](bool success, bool last) {
                                  EXPECT_FALSE(success);
                                  EXPECT_FALSE(last);
                                }));
}

TEST_P(WorkerClientTest, LoadSnapshot) {
  auto response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  writer.AppendBool(result());
  writer.AppendBool(result());

  ExpectLoadSnapshot(kFakeAccountID, response.get());
  worker_client()->LoadSnapshot(kFakeAccountID,
                                base::Bind(
                                    [](bool expected_result, bool expected_last,
                                       bool success, bool last) {
                                      EXPECT_EQ(expected_result, success);
                                      EXPECT_EQ(expected_last, last);
                                    },
                                    result(), result()));
}

INSTANTIATE_TEST_SUITE_P(WorkerClientTest, WorkerClientTest, testing::Bool());
}  // namespace data_snapshotd
}  // namespace arc
