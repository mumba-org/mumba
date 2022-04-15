// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_launch_interface.h"

#include <memory>
#include "dbus/scoped_dbus_error.h"

#include <dbus/object_path.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/message.h>
#include <dbus/vm_launch/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <vm_concierge/proto_bindings/concierge_service.pb.h>
#include <vm_launch/proto_bindings/launch.pb.h>

namespace vm_tools {
namespace concierge {
namespace {

using testing::_;

dbus::Bus::Options GetDbusOptions() {
  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  return opts;
}

class VmLaunchInterfaceTest : public testing::Test {
 public:
  VmLaunchInterfaceTest()
      : mock_bus_(new dbus::MockBus(GetDbusOptions())),
        mock_proxy_(new dbus::MockObjectProxy(
            mock_bus_.get(),
            launch::kVmLaunchServiceName,
            dbus::ObjectPath(launch::kVmLaunchServicePath))) {
    EXPECT_CALL(*mock_bus_.get(),
                GetObjectProxy(launch::kVmLaunchServiceName,
                               dbus::ObjectPath(launch::kVmLaunchServicePath)))
        .WillRepeatedly(testing::Return(mock_proxy_.get()));
  }

 protected:
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_proxy_;
};

}  // namespace

TEST_F(VmLaunchInterfaceTest, FailureReturnsEmpty) {
  VmLaunchInterface launch_interface(mock_bus_);

  EXPECT_CALL(*mock_proxy_.get(), CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(
          testing::Invoke([](dbus::MethodCall* method_call, int timeout_ms,
                             dbus::ScopedDBusError* error) {
            error->get()->name = DBUS_ERROR_FAILED;
            error->get()->message = "test error";
            return nullptr;
          }));

  VmId id("test_owner_id", "test_vm_name");
  EXPECT_EQ(launch_interface.GetWaylandSocketForVm(id, VmInfo::UNKNOWN), "");
}

TEST_F(VmLaunchInterfaceTest, SuccessReturnsNonEmpty) {
  VmLaunchInterface launch_interface(mock_bus_);

  EXPECT_CALL(*mock_proxy_.get(), CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(
          testing::Invoke([](dbus::MethodCall* method_call, int timeout_ms,
                             dbus::ScopedDBusError* error) {
            EXPECT_EQ(method_call->GetMember(),
                      launch::kVmLaunchServiceStartWaylandServerMethod);

            launch::StartWaylandServerResponse response_proto;
            response_proto.mutable_server()->set_path("test_path");

            std::unique_ptr<dbus::Response> response =
                dbus::Response::CreateEmpty();
            dbus::MessageWriter(response.get())
                .AppendProtoAsArrayOfBytes(response_proto);
            return response;
          }));

  VmId id("test_owner_id", "test_vm_name");
  EXPECT_EQ(launch_interface.GetWaylandSocketForVm(id, VmInfo::UNKNOWN),
            "test_path");
}

}  // namespace concierge
}  // namespace vm_tools
