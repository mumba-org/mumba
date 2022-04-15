// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/data-snapshotd/upstart_client.h"

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::WithArgs;

namespace arc {
namespace data_snapshotd {

namespace {

// constexpr char kFakeAccountID[] = "fake@account.id";

const std::vector<std::string> kFakeEnvironment = {"env1=var1", "env2=var2"};

}  // namespace

class UpstartClientTest : public testing::Test {
 public:
  UpstartClientTest() : bus_(new dbus::MockBus{dbus::Bus::Options{}}) {
    object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), UpstartClient::service_name_for_testing(),
        dbus::ObjectPath(UpstartClient::worker_daemon_job_path_for_testing()));
    response_ = dbus::Response::CreateEmpty();
  }

  void SetUp() override {
    upstart_client_ = std::make_unique<UpstartClient>(bus_);
  }

  void TearDown() override { upstart_client_.reset(); }

  // Set a D-Bus object proxy expectation on start/stop |method| of
  // arc-data-snapshotd-worker upstart job.
  void ExpectCall(const std::string& method,
                  const std::vector<std::string>& expected_environment) {
    EXPECT_CALL(*bus_,
                GetObjectProxy(
                    UpstartClient::service_name_for_testing(),
                    dbus::ObjectPath(
                        UpstartClient::worker_daemon_job_path_for_testing())))
        .WillOnce(Return(object_proxy_.get()));
    auto* dbus_response = response_.get();
    EXPECT_CALL(*object_proxy_, DoCallMethod(_, _, _))
        .WillOnce(WithArgs<0, 2>(
            Invoke([method, expected_environment, dbus_response](
                       dbus::MethodCall* call,
                       base::OnceCallback<void(dbus::Response*)>* callback) {
              EXPECT_EQ(call->GetInterface(),
                        UpstartClient::job_interface_for_testing());
              EXPECT_EQ(call->GetMember(), method);
              dbus::MessageReader reader(call);
              std::vector<std::string> environment;
              ASSERT_TRUE(reader.PopArrayOfStrings(&environment));
              EXPECT_EQ(environment, expected_environment);
              bool wait_for_response;
              ASSERT_TRUE(reader.PopBool(&wait_for_response));
              EXPECT_TRUE(wait_for_response);

              std::move(*callback).Run(dbus_response);
            })));
  }
  UpstartClient* upstart_client() { return upstart_client_.get(); }

 private:
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> object_proxy_;
  std::unique_ptr<UpstartClient> upstart_client_;
  std::unique_ptr<dbus::Response> response_;
};

TEST_F(UpstartClientTest, StartWorkerDaemon) {
  ExpectCall(UpstartClient::start_method_for_testing(), kFakeEnvironment);
  upstart_client()->StartWorkerDaemon(
      kFakeEnvironment, base::Bind([](bool success) { EXPECT_TRUE(success); }));
}

TEST_F(UpstartClientTest, StopWorkerDaemon) {
  ExpectCall(UpstartClient::stop_method_for_testing(), {});
  upstart_client()->StopWorkerDaemon();
}

}  // namespace data_snapshotd
}  // namespace arc
